//! Thin, typed wrappers around the system tools `hyperion-agent` needs to call.
//!
//! Every public function in this crate:
//! - takes pre-validated typed arguments,
//! - shells out only via `Command::new(..).arg(..)` (no `sh -c`),
//! - is idempotent (ensure-X style, no-ops if state already matches),
//! - returns a `RollbackToken` for any state-mutating step.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![forbid(unsafe_code)]

pub mod acme;
pub mod backup;
pub mod cmd;
pub mod email;
pub mod fs;
pub mod ftp;
pub mod mariadb;
pub mod nginx;
pub mod nodejs;
pub mod phpfpm;
pub mod postfix;
pub mod postgres;
pub mod rollback;
pub mod ssh;
pub mod users;
pub mod wpcli;

pub mod files;

/// Rich systemd unit status. Returned by [`systemctl_status`] so
/// callers can distinguish "down" from "currently restarting" — the
/// boolean active alone collapsed both into the same state and
/// gave operators "down + stop-sigterm" false alarms on every
/// restart.
#[derive(Debug, Clone)]
pub struct UnitStatus {
    /// True for any of: `active`, `activating`, `reloading`,
    /// `deactivating`. False for `inactive` / `failed` / probe
    /// error. UI consumers usually want `active && !transient`
    /// to colour the row green.
    pub active: bool,
    /// True for any UnitFileState that autostarts the unit:
    /// enabled / enabled-runtime / alias / static / indirect /
    /// generated / transient.
    pub enabled: bool,
    /// Raw systemd ActiveState — "active" | "activating" |
    /// "reloading" | "deactivating" | "inactive" | "failed".
    /// Drives the "restarting…" badge in the UI.
    pub active_state: String,
    /// Raw systemd SubState — "running" | "dead" | "exited" |
    /// "start-pre" | "stop-sigterm" | "auto-restart" | "failed" …
    /// One-word free-form diagnostic surface.
    pub sub_state: String,
    /// Raw systemd UnitFileState — "enabled" | "disabled" |
    /// "static" | "indirect" | "generated" | "masked" | … |
    /// empty string when the unit isn't installed.
    pub unit_file_state: String,
}

impl UnitStatus {
    /// `true` if the unit is in a brief transition (start/stop/
    /// reload) — UI should show "restarting" not "down".
    pub fn transient(&self) -> bool {
        matches!(
            self.active_state.as_str(),
            "activating" | "reloading" | "deactivating"
        )
    }
}

/// Probe one systemd unit's status via `systemctl show`.
///
/// The old implementation used `is-active --quiet` + `is-enabled
/// --quiet` and reported false for any non-success exit. That gave
/// two false negatives we kept hitting on s4:
///
///   - `is-active` exits 0 ONLY for `active` — `activating`,
///     `reloading`, `deactivating` all exit non-zero, so a probe
///     that lands mid-restart marks the unit "down" with sub_state
///     "stop-sigterm" even though it'll be back up in 100ms.
///
///   - `is-enabled` exits 0 only for plain `enabled` /
///     `enabled-runtime` / `alias`. `static` / `indirect` /
///     `generated` (legitimate ways for a service to autostart)
///     all exit non-zero, so the UI flagged enabled-via-WantedBy
///     services as "enabled=no".
///
/// New approach: one `systemctl show -p ActiveState -p SubState
/// -p UnitFileState --value` call. Parses the structured output
/// and maps it correctly. Returns `UnitStatus` with both the
/// derived booleans + the raw strings so the UI can distinguish
/// "restarting" from "down".
pub async fn systemctl_status_rich(unit: &str) -> UnitStatus {
    let out = tokio::process::Command::new("/usr/bin/systemctl")
        .args([
            "show",
            "-p", "ActiveState",
            "-p", "SubState",
            "-p", "UnitFileState",
            "--value",
            "--no-pager",
            unit,
        ])
        .output()
        .await;
    let unknown = |reason: &str| UnitStatus {
        active: false,
        enabled: false,
        active_state: "unknown".into(),
        sub_state: reason.into(),
        unit_file_state: String::new(),
    };
    let Ok(out) = out else {
        return unknown("spawn-failed");
    };
    if !out.status.success() {
        // Exit 4 = "not loaded / no such unit". That maps to
        // `inactive + dead + ""` in systemd's own data model;
        // surface accordingly so consumers can distinguish "we
        // don't know" from "service is genuinely missing".
        return unknown("no-such-unit");
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut lines = stdout.lines();
    let active_state = lines.next().unwrap_or("").trim().to_string();
    let sub_state = lines.next().unwrap_or("").trim().to_string();
    let unit_file_state = lines.next().unwrap_or("").trim().to_string();

    let active = matches!(
        active_state.as_str(),
        "active" | "activating" | "reloading" | "deactivating"
    );
    let enabled = matches!(
        unit_file_state.as_str(),
        "enabled" | "enabled-runtime" | "alias" | "static"
            | "indirect" | "generated" | "transient"
    );
    let sub = if sub_state.is_empty() {
        "?".into()
    } else {
        sub_state
    };
    UnitStatus {
        active,
        enabled,
        active_state,
        sub_state: sub,
        unit_file_state,
    }
}

/// Backwards-compatible adapter for callers that only want the
/// `(active, enabled, sub_state)` triple. New code should use
/// [`systemctl_status_rich`] instead.
pub async fn systemctl_status(unit: &str) -> (bool, bool, String) {
    let s = systemctl_status_rich(unit).await;
    (s.active, s.enabled, s.sub_state)
}

/// Is a unit file present at all on the system?
///
/// Four checks in order — first true wins, so we save subprocess
/// roundtrips in the common case:
///   1. `systemctl cat <unit>` exits 0 iff the unit file exists on
///      disk (works for vendor-shipped + drop-in units). MOST
///      RELIABLE — doesn't depend on `list-unit-files`'s output
///      formatting, which varies by systemd version.
///   2. `systemctl is-active --quiet` succeeds → the unit is
///      definitely present (you can't activate something that
///      doesn't exist).
///   3. **Templated-instance match** — Debian's PostgreSQL ships as
///      `postgresql@15-main.service`, not bare `postgresql.service`.
///      `systemctl list-units --no-pager --no-legend` shows running
///      instances; if any line starts with `<unit>@`, that template
///      is present.
///   4. `systemctl list-unit-files <unit>` table tolerant match
///      (handles ANSI colour codes + indentation).
pub async fn systemctl_unit_present(unit: &str) -> bool {
    // 1. cat — most authoritative.
    if let Ok(out) = tokio::process::Command::new("/usr/bin/systemctl")
        .args(["cat", "--no-pager", unit])
        .output()
        .await
    {
        if out.status.success() && !out.stdout.is_empty() {
            return true;
        }
    }
    // 2. is-active. If the unit is running, it exists.
    if let Ok(s) = tokio::process::Command::new("/usr/bin/systemctl")
        .args(["is-active", "--quiet", unit])
        .status()
        .await
    {
        if s.success() {
            return true;
        }
    }
    // 3. Templated-instance match. Debian PostgreSQL doesn't run
    //    `postgresql.service` directly; it runs
    //    `postgresql@<version>-<cluster>.service` (e.g.
    //    postgresql@15-main.service). Same pattern for getty@,
    //    systemd-fsck@, and others.
    //
    //    `systemctl list-units --no-legend <unit>@*.service` lists
    //    every running instance. Any hit means the template (and
    //    therefore the unit) is present.
    if let Ok(out) = tokio::process::Command::new("/usr/bin/systemctl")
        .args([
            "list-units",
            "--no-pager",
            "--no-legend",
            "--all",
            "--type=service",
            &format!("{unit}@*"),
        ])
        .output()
        .await
    {
        let stdout = String::from_utf8_lossy(&out.stdout);
        if templated_instance_present(&stdout, unit) {
            return true;
        }
    }
    // Also check if the @ template unit file itself exists on disk.
    if let Ok(out) = tokio::process::Command::new("/usr/bin/systemctl")
        .args(["cat", "--no-pager", &format!("{unit}@.service")])
        .output()
        .await
    {
        if out.status.success() && !out.stdout.is_empty() {
            return true;
        }
    }
    // 4. Tolerant `list-unit-files` parse. systemd ships output like
    //
    //     UNIT FILE              STATE   VENDOR PRESET
    //     nginx.service          enabled enabled
    //
    //     1 unit files listed.
    //
    // The unit-name line has variable leading whitespace on some
    // builds + may carry ANSI colour. `contains()` of `unit` plus
    // either ".service" or "enabled"/"disabled" is robust without
    // matching the header.
    let out = tokio::process::Command::new("/usr/bin/systemctl")
        .args(["list-unit-files", "--no-pager", "--no-legend", unit])
        .output()
        .await;
    let Ok(o) = out else { return false };
    let stdout = String::from_utf8_lossy(&o.stdout);
    let unit_with_suffix = format!("{unit}.service");
    stdout.lines().any(|raw| {
        let l = strip_ansi(raw.trim());
        l.starts_with(&unit_with_suffix) || l.starts_with(unit)
    })
}

/// True if the `systemctl list-units` output mentions a templated
/// instance of `unit` (e.g. `postgresql@15-main.service` for
/// `postgresql`). Pulled out into a pure helper so the parsing rule
/// can be unit-tested without mocking systemctl.
///
/// Tolerates leading whitespace and ANSI colour codes (some systemd
/// builds emit them even with --no-legend), and rejects lines that
/// merely *contain* the unit name (e.g. `apt-daily-postgresql.service`).
pub(crate) fn templated_instance_present(stdout: &str, unit: &str) -> bool {
    let prefix = format!("{unit}@");
    stdout.lines().any(|raw| {
        let l = strip_ansi(raw.trim());
        // Drop a leading bullet "●" + space that systemctl emits when
        // the unit is failed/active — its raw bytes can survive
        // strip_ansi because it isn't a CSI sequence.
        let l = l.trim_start_matches('●').trim_start();
        l.starts_with(&prefix)
    })
}

/// Strip ANSI CSI sequences ("\x1b[…m") that some systemctl builds
/// emit when stdout is a TTY-ish pipe. Pure-stdlib so no extra crate.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // Skip until 'm' (CSI termination char we care about).
            for next in chars.by_ref() {
                if next == 'm' {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

#[derive(Debug, thiserror::Error)]
pub enum AdapterError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("command {cmd} failed with exit {code}: {stderr_tail}")]
    Command {
        cmd: String,
        code: i32,
        stderr_tail: String,
    },
    #[error("template render: {0}")]
    Render(#[from] askama::Error),
    #[error("validation: {0}")]
    Validation(#[from] hyperion_validate::ValidationError),
    #[error("acme: {0}")]
    Acme(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("other: {0}")]
    Other(String),
}

impl From<AdapterError> for hyperion_rpc::RpcError {
    fn from(e: AdapterError) -> Self {
        match e {
            AdapterError::Command {
                cmd,
                code,
                stderr_tail,
            } => hyperion_rpc::RpcError::SystemCommand {
                cmd,
                code,
                stderr_tail,
            },
            AdapterError::Conflict(m) => hyperion_rpc::RpcError::Conflict { message: m },
            AdapterError::Validation(v) => v.into(),
            AdapterError::Render(e) => hyperion_rpc::RpcError::ProvisioningFailed {
                stage: "template".into(),
                reason: e.to_string(),
            },
            AdapterError::Acme(m) => hyperion_rpc::RpcError::ProvisioningFailed {
                stage: "acme".into(),
                reason: m,
            },
            AdapterError::Io(e) => hyperion_rpc::RpcError::ProvisioningFailed {
                stage: "io".into(),
                reason: e.to_string(),
            },
            AdapterError::Other(m) => hyperion_rpc::RpcError::ProvisioningFailed {
                stage: "other".into(),
                reason: m,
            },
        }
    }
}

/// Random password generator: 32 chars from [A-Za-z0-9].
pub fn random_password() -> String {
    use rand::Rng;
    let alphabet: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::thread_rng();
    let mut s = String::with_capacity(32);
    for _ in 0..32 {
        let idx = rng.gen_range(0..alphabet.len());
        s.push(alphabet[idx] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// UnitStatus.transient detects the three ActiveState values
    /// systemd uses while a unit is in motion. The bug we just
    /// fixed: a probe that lands on `deactivating + stop-sigterm`
    /// during a restart marked the unit "down" even though the
    /// restart was about to complete. Now it's flagged transient
    /// and severity stays "ok".
    #[test]
    fn unit_status_transient_covers_all_motion_states() {
        for s in ["activating", "reloading", "deactivating"] {
            let us = UnitStatus {
                active: true,
                enabled: true,
                active_state: s.to_string(),
                sub_state: "start-pre".into(),
                unit_file_state: "enabled".into(),
            };
            assert!(us.transient(), "expected transient for {s}");
        }
        for s in ["active", "inactive", "failed", "unknown"] {
            let us = UnitStatus {
                active: false,
                enabled: false,
                active_state: s.to_string(),
                sub_state: "?".into(),
                unit_file_state: String::new(),
            };
            assert!(!us.transient(), "expected non-transient for {s}");
        }
    }

    /// strip_ansi must remove the colour codes systemctl sometimes
    /// emits without dropping legitimate content. The bug we shipped
    /// before this fix: a unit-files line came out as
    /// "\x1b[1mnginx.service\x1b[0m enabled enabled" and
    /// starts_with("nginx") failed because of the leading CSI.
    #[test]
    fn strip_ansi_removes_csi_sequences_and_preserves_text() {
        assert_eq!(strip_ansi("nginx.service enabled"), "nginx.service enabled");
        assert_eq!(
            strip_ansi("\x1b[1mnginx.service\x1b[0m enabled enabled"),
            "nginx.service enabled enabled"
        );
        assert_eq!(strip_ansi(""), "");
        // Multi-byte UTF-8 around an escape sequence — characters either
        // side of the escape survive.
        assert_eq!(
            strip_ansi("\x1b[31mčeština\x1b[0m"),
            "čeština"
        );
        // Bare ESC with no terminator: consume to end of string rather
        // than panicking.
        assert_eq!(strip_ansi("nginx\x1b["), "nginx");
    }

    #[test]
    fn random_password_is_32_alnum() {
        let p = random_password();
        assert_eq!(p.len(), 32);
        assert!(p.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn random_passwords_differ() {
        let a = random_password();
        let b = random_password();
        assert_ne!(a, b);
    }

    /// Templated-instance detection: the s4 regression was postgresql
    /// running as `postgresql@15-main.service` while the bare
    /// `postgresql.service` doesn't exist, so the 3-tier check missed
    /// it. This locks in the parse rule that fixes that.
    #[test]
    fn templated_instance_matches_postgresql_at_15_main() {
        let stdout = "  postgresql@15-main.service    loaded active running PostgreSQL Cluster 15-main\n";
        assert!(templated_instance_present(stdout, "postgresql"));
    }

    #[test]
    fn templated_instance_tolerates_ansi_and_bullet() {
        // Real systemctl output on a failed instance carries a "●"
        // bullet + bold ANSI before the unit name.
        let stdout = "● \x1b[1mpostgresql@15-main.service\x1b[0m loaded failed failed PostgreSQL Cluster 15-main\n";
        assert!(templated_instance_present(stdout, "postgresql"));
    }

    #[test]
    fn templated_instance_rejects_unrelated_units_with_substring() {
        // `apt-daily-postgresql.service` contains "postgresql" but
        // isn't an @-instance of it — must not match.
        let stdout = "  apt-daily-postgresql.service loaded active waiting Daily apt activity\n";
        assert!(!templated_instance_present(stdout, "postgresql"));
    }

    #[test]
    fn templated_instance_empty_output_is_false() {
        assert!(!templated_instance_present("", "postgresql"));
    }

    #[test]
    fn templated_instance_multiple_at_pattern_units() {
        // Multiple templates (getty@tty1, getty@tty2) — any hit suffices.
        let stdout = "\
            getty@tty1.service loaded active running Getty on tty1\n\
            getty@tty2.service loaded active running Getty on tty2\n";
        assert!(templated_instance_present(stdout, "getty"));
    }

    #[test]
    fn adapter_error_to_rpc_error_command() {
        let a = AdapterError::Command {
            cmd: "useradd".into(),
            code: 1,
            stderr_tail: "boom".into(),
        };
        let r: hyperion_rpc::RpcError = a.into();
        match r {
            hyperion_rpc::RpcError::SystemCommand { cmd, code, .. } => {
                assert_eq!(cmd, "useradd");
                assert_eq!(code, 1);
            }
            other => panic!("wrong: {other:?}"),
        }
    }
}
