//! `GET /settings/backups` — what is kept, where off-site copies go, how long
//! everything stays, what happens to a deleted site, and the one-off copy of
//! backups that never left.
//!
//! This URL used to be a separate "Backup targets" page for the S3 targets,
//! while the FTP target, retention and trash sat on a tab of the one-page
//! Settings. Both kinds of destination are pushed right after each backup, so
//! they are now one table ([`ftp_row`], [`s3_row`]) with the two forms beside
//! it.
//!
//! Two different rights write here. The agent.toml cards (what is kept, the
//! FTP target, retention, trash) are Owner-only like the rest of Settings;
//! the S3 targets and the backfill need `BackupTargets`, which an
//! Administrator holds. The page is open to either, and each group is
//! read-only for whoever lacks its right.

use super::chrome::{self, Chrome, PageQuery};
use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::state::SharedState;
use askama::Template;
use axum::extract::{Query, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use hyperion_state::capabilities::Capability;
use hyperion_types::{AgentConfigView, BackupConfigView, BackupRemoteConfigView, BackupTargetView};

/// A status pill: its tone class and its word. Never colour alone — the word
/// carries the state.
pub struct Pill {
    pub cls: &'static str,
    pub word: String,
}

fn pill(cls: &'static str, word: impl Into<String>) -> Pill {
    Pill {
        cls,
        word: word.into(),
    }
}

/// The FTP / FTPS / SFTP destination, as a row of the targets table.
pub struct FtpRow {
    /// Anything to list: a host is set, or the switch is on without one.
    pub shown: bool,
    /// "FTP", "FTPS" or "SFTP".
    pub protocol: String,
    /// `sftp://user@host:22/base` — the password is never part of it.
    pub address: String,
    pub encryption: Pill,
    /// Title for the encryption pill: what it does and does not cover.
    pub encryption_note: &'static str,
    pub state: Pill,
    /// Why it takes no copy although it is switched on; empty otherwise.
    pub problem: String,
    /// It receives a copy of every backup.
    pub active: bool,
}

/// One S3 target, as a row of the targets table. Also carries what the
/// edit button pre-fills the S3 form with (never the secret).
pub struct S3Row {
    pub id: i64,
    pub name: String,
    pub endpoint: String,
    pub bucket: String,
    pub region: String,
    pub access_key_id: String,
    /// The age public key, "" for none.
    pub age_recipient: String,
    pub enabled: bool,
    /// `retention_daily`: newest N per site kept on the target, 0 = all.
    pub keep_n: i64,
    /// What stays on the target, in words.
    pub keep: String,
    pub encryption: Pill,
    pub encryption_note: &'static str,
    pub state: Pill,
    /// Why it takes no copy; empty when it does or is simply switched off.
    pub problem: String,
    pub active: bool,
}

/// The FTP target's row. Mirrors what the backup run does with
/// `[backup_remote]`: with the switch on every backup is pushed, which only
/// lands anywhere when a host is set.
pub fn ftp_row(r: &BackupRemoteConfigView) -> FtpRow {
    let host = r.host.trim();
    let scheme = match r.scheme.trim().to_ascii_lowercase().as_str() {
        "" => "ftp".to_string(),
        s => s.to_string(),
    };
    let base = r.base_path.trim();
    let base = if base.starts_with('/') {
        base.to_string()
    } else {
        format!("/{base}")
    };
    let user = r.user.trim();
    let address = if host.is_empty() {
        String::new()
    } else if user.is_empty() {
        format!("{scheme}://{host}:{}{base}", r.port)
    } else {
        format!("{scheme}://{user}@{host}:{}{base}", r.port)
    };
    let (encryption, encryption_note) = match scheme.as_str() {
        "sftp" | "ftps" => (
            pill("muted", "encrypted in transit"),
            "Encrypted on the way; stored on that server as it was sent",
        ),
        _ => (
            pill("warn", "not encrypted"),
            "Plain FTP: the password and every backup travel unencrypted",
        ),
    };
    let (state, problem, active) = match (r.enabled, host.is_empty()) {
        (true, false) => (pill("ok", "on"), String::new(), true),
        (true, true) => (
            pill("warn", "no server"),
            "Switched on, but no host is set, so every copy fails.".to_string(),
            false,
        ),
        (false, _) => (pill("muted", "off"), String::new(), false),
    };
    FtpRow {
        shown: !host.is_empty() || r.enabled,
        protocol: scheme.to_ascii_uppercase(),
        address,
        encryption,
        encryption_note,
        state,
        problem,
        active,
    }
}

/// One S3 target's row. `secret_on_disk`: its secret key file is present on
/// this master. The reasons mirror the filter the backup run uses
/// (`hostings::resolve_s3_targets`): anything it skips is shown as taking no
/// copy, with the reason, rather than as "on".
pub fn s3_row(t: BackupTargetView, secret_on_disk: bool) -> S3Row {
    let (encryption, encryption_note) = match t.age_recipient.as_deref().map(str::trim) {
        Some(r) if !r.is_empty() => (
            pill("ok", "encrypted (age)"),
            "Encrypted on the node before upload; only the private key opens it",
        ),
        _ => (
            pill("warn", "not encrypted"),
            "Stored readable by anyone who holds the bucket's keys",
        ),
    };
    let keep = match t.retention_daily {
        n if n <= 0 => "all kept, never pruned".to_string(),
        n => format!("newest {n} per site"),
    };
    let (state, problem, active) = if t.kind != "s3" {
        (
            pill("warn", "not used"),
            format!(
                "A \u{201c}{}\u{201d} target: only S3 targets receive backups. Edit it to make it one.",
                t.kind
            ),
            false,
        )
    } else if !t.enabled {
        (pill("muted", "off"), String::new(), false)
    } else if t.secret_key_id.is_none() {
        (
            pill("err", "no secret key"),
            "Nothing is sent until it has one: edit it and paste the secret key.".to_string(),
            false,
        )
    } else if !secret_on_disk {
        (
            pill("err", "secret key missing"),
            "Its key file is gone from the master, so nothing is sent: edit it and paste the \
             secret key again."
                .to_string(),
            false,
        )
    } else {
        (pill("ok", "on"), String::new(), true)
    };
    S3Row {
        id: t.id,
        name: t.name,
        endpoint: t.endpoint,
        bucket: t.bucket,
        region: t.region,
        access_key_id: t.access_key_id,
        age_recipient: t.age_recipient.unwrap_or_default(),
        enabled: t.enabled,
        keep_n: t.retention_daily.max(0),
        keep,
        encryption,
        encryption_note,
        state,
        problem,
        active,
    }
}

/// The pill on "Off-site targets": how many destinations take a copy.
/// `targets_known`: the S3 list was read. `snapshots_only`: no archives are
/// made at all, so no target receives anything however many are on.
pub fn offsite_pill(active: usize, targets_known: bool, snapshots_only: bool) -> Pill {
    if snapshots_only {
        return pill("warn", "unused — snapshots only");
    }
    match (active, targets_known) {
        (0, true) => pill("warn", "nothing off-site"),
        (0, false) => pill("muted", "unknown"),
        (1, _) => pill("ok", "1 in use"),
        (n, _) => pill("ok", format!("{n} in use")),
    }
}

/// The pill on "What is kept".
pub fn protection_pill(mode: &str) -> Pill {
    match mode {
        "backups" => pill("ok", "archives only"),
        "snapshots" => pill("warn", "snapshots only"),
        _ => pill("ok", "archives and snapshots"),
    }
}

/// The pill on "Local copies".
pub fn local_copies_pill(b: &BackupConfigView) -> Pill {
    match (b.drop_local_after_offsite, b.keep_local_latest) {
        (false, _) => pill("ok", "kept"),
        (true, n) if n > 0 => pill("muted", format!("newest {n} kept")),
        (true, _) => pill("muted", "deleted once off-site"),
    }
}

/// The pill on "Archive retention". In snapshots-only mode no archives are
/// made, so the rule governs nothing new.
pub fn retention_pill(max_age_days: i64, keep_latest_n: i64, snapshots_only: bool) -> Pill {
    if snapshots_only {
        return pill("muted", "no archives made");
    }
    let days = if max_age_days == 1 {
        "1 day".to_string()
    } else {
        format!("{max_age_days} days")
    };
    pill("ok", format!("{days} · newest {keep_latest_n} kept"))
}

/// The pill on "Trash".
pub fn trash_pill(enabled: bool, days: i64) -> Pill {
    match (enabled, days) {
        (false, _) => pill("muted", "off"),
        (true, 1) => pill("ok", "on · 1 day"),
        (true, d) => pill("ok", format!("on · {d} days")),
    }
}

#[derive(Template)]
#[template(path = "settings_backups.html")]
struct BackupsTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    chrome: Chrome,
    csrf_token: String,
    config: AgentConfigView,
    config_error: Option<String>,
    /// Why the S3 targets could not be read; the table then lacks them.
    targets_error: Option<String>,
    ftp: FtpRow,
    s3: Vec<S3Row>,
    /// Destinations that take a copy right now.
    active_targets: usize,
    snapshots_only: bool,
    offsite: Pill,
    protection: Pill,
    local: Pill,
    retention: Pill,
    trash: Pill,
    /// May add, edit, test and delete S3 targets.
    can_targets: bool,
    /// The user lacks the Settings permission (they are here for the S3
    /// targets): the agent.toml cards and the FTP row are not rendered and
    /// `config` holds defaults, never the real values.
    config_hidden: bool,
    /// S3 targets withheld from a user without the backup-targets right
    /// (their endpoints, buckets and access key ids are that right's).
    s3_hidden: usize,
    /// May run the backfill: the targets right AND every site in scope,
    /// which the handler also demands.
    can_backfill: bool,
    /// Set by the redirect after saving the FTP target: re-run its check
    /// once the agent is back.
    auto_probe_backup_remote: bool,
}

pub async fn get_backups(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Query(q): Query<PageQuery>,
) -> Result<Response, AppError> {
    let can_targets = ctx.can(Capability::BackupTargets);
    if !ctx.can(Capability::SettingsManage) && !can_targets {
        return Ok(Redirect::to("/").into_response());
    }
    let ((chrome, _nodes), config_res, targets_res) = tokio::join!(
        chrome::chrome(&state, &ctx, "backups", &q),
        hyperion_rpc_client::call(&state.agent_socket, Request::AgentConfigView),
        hyperion_rpc_client::call(&state.agent_socket, Request::BackupTargetList),
    );
    let can_settings = ctx.can(Capability::SettingsManage);
    let (config, config_error) = if can_settings {
        super::config_or_default(config_res)
    } else {
        (hyperion_types::AgentConfigView::default(), None)
    };
    let (targets, targets_error) = match targets_res {
        Ok(RpcResponse::BackupTargetList(v)) => (v, None),
        Ok(RpcResponse::Error(e)) => (Vec::new(), Some(e.to_string())),
        Ok(_) => (Vec::new(), Some("unexpected agent response".to_string())),
        Err(e) => (Vec::new(), Some(format!("rpc: {e}"))),
    };
    // The secret file is stat'd, never read: the page has no business
    // holding the plaintext. Same check the per-site target picker makes.
    let mut s3 = Vec::with_capacity(targets.len());
    for t in targets {
        let on_disk = match t.secret_key_id.as_deref() {
            Some(p) => tokio::fs::metadata(p).await.is_ok(),
            None => false,
        };
        s3.push(s3_row(t, on_disk));
    }
    let ftp = ftp_row(&config.backup_remote);
    // Counted before hiding, so the page can say what it withheld; the
    // active-target count below still sees them (it is a number, not data).
    let active_targets = usize::from(ftp.active) + s3.iter().filter(|r| r.active).count();
    let s3_hidden = if can_targets { 0 } else { s3.len() };
    let s3 = if can_targets { s3 } else { Vec::new() };
    let snapshots_only = config.cluster.protection_mode == "snapshots";
    let tpl = BackupsTpl {
        username: &ctx.username,
        user_initial: crate::handlers::user_initial(&ctx.username),
        active: "settings",
        css_version: crate::handlers::css_version(),
        htmx_version: crate::handlers::htmx_version(),
        chrome,
        csrf_token: crate::handlers::session_csrf_token(&state, &ctx),
        offsite: offsite_pill(active_targets, targets_error.is_none(), snapshots_only),
        protection: protection_pill(&config.cluster.protection_mode),
        local: local_copies_pill(&config.backup),
        retention: retention_pill(
            config.backup_retention.max_age_days,
            config.backup_retention.keep_latest_n,
            snapshots_only,
        ),
        trash: trash_pill(
            config.cluster.trash_enabled,
            config.cluster.trash_retention_days,
        ),
        active_targets,
        snapshots_only,
        ftp,
        s3,
        targets_error,
        config,
        config_error,
        can_targets,
        config_hidden: !can_settings,
        s3_hidden,
        can_backfill: can_targets && ctx.scope_all(),
        auto_probe_backup_remote: q.probe_backup_remote.is_some(),
    };
    Ok(Html(tpl.render()?).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn remote(
        enabled: bool,
        scheme: &str,
        host: &str,
        user: &str,
        base: &str,
    ) -> BackupRemoteConfigView {
        BackupRemoteConfigView {
            enabled,
            scheme: scheme.into(),
            host: host.into(),
            port: 22,
            user: user.into(),
            password_set: true,
            base_path: base.into(),
        }
    }

    fn target(
        kind: &str,
        enabled: bool,
        secret: Option<&str>,
        age: Option<&str>,
        keep: i64,
    ) -> BackupTargetView {
        BackupTargetView {
            id: 7,
            name: "wasabi-eu".into(),
            kind: kind.into(),
            endpoint: "https://s3.eu-central-1.wasabisys.com".into(),
            bucket: "hyperion-prod".into(),
            region: "eu-central-1".into(),
            access_key_id: "AKIA".into(),
            secret_key_id: secret.map(Into::into),
            age_recipient: age.map(Into::into),
            retention_daily: keep,
            retention_weekly: 0,
            retention_monthly: 0,
            enabled,
            created_at: 0,
            updated_at: 0,
        }
    }

    #[test]
    fn the_ftp_address_never_carries_the_password_and_always_has_a_path() {
        let r = ftp_row(&remote(
            true,
            "sftp",
            "backup.example",
            "hyp",
            "/srv/backups",
        ));
        assert_eq!(r.address, "sftp://hyp@backup.example:22/srv/backups");
        assert_eq!(r.protocol, "SFTP");
        assert!(r.active && r.shown);
        assert_eq!(r.state.word, "on");
        let r = ftp_row(&remote(true, "ftp", "backup.example", "", "hyperion"));
        assert_eq!(r.address, "ftp://backup.example:22/hyperion");
        let r = ftp_row(&remote(false, "ftps", "backup.example", "u", ""));
        assert_eq!(r.address, "ftps://u@backup.example:22/");
    }

    #[test]
    fn an_ftp_target_without_a_host_is_not_listed_unless_switched_on() {
        let r = ftp_row(&remote(false, "ftp", "", "", ""));
        assert!(!r.shown && !r.active);
        let r = ftp_row(&remote(true, "ftp", " ", "", ""));
        assert!(
            r.shown,
            "an 'on' switch with nowhere to send must be visible"
        );
        assert!(!r.active);
        assert_eq!(r.state.cls, "warn");
        assert!(!r.problem.is_empty());
        let r = ftp_row(&remote(false, "sftp", "h", "u", "/b"));
        assert!(r.shown && !r.active);
        assert_eq!(r.state.word, "off");
    }

    #[test]
    fn plain_ftp_is_flagged_unencrypted() {
        assert_eq!(
            ftp_row(&remote(true, "ftp", "h", "u", "/")).encryption.cls,
            "warn"
        );
        assert_eq!(
            ftp_row(&remote(true, "FTPS", "h", "u", "/"))
                .encryption
                .word,
            "encrypted in transit"
        );
        assert_eq!(
            ftp_row(&remote(true, "sftp", "h", "u", "/"))
                .encryption
                .word,
            "encrypted in transit"
        );
    }

    #[test]
    fn an_s3_target_is_on_only_when_the_backup_run_would_use_it() {
        let ok = s3_row(
            target(
                "s3",
                true,
                Some("/etc/hyperion/secrets/x"),
                Some("age1x"),
                7,
            ),
            true,
        );
        assert!(ok.active);
        assert_eq!(ok.state.word, "on");
        assert!(ok.problem.is_empty());

        let off = s3_row(target("s3", false, Some("/x"), None, 7), true);
        assert!(!off.active);
        assert_eq!(off.state.word, "off");
        assert!(
            off.problem.is_empty(),
            "switched off is a choice, not a problem"
        );

        let no_secret = s3_row(target("s3", true, None, None, 7), false);
        assert!(!no_secret.active);
        assert_eq!(no_secret.state.cls, "err");

        let gone = s3_row(target("s3", true, Some("/x"), None, 7), false);
        assert!(!gone.active);
        assert_eq!(gone.state.word, "secret key missing");

        let local = s3_row(target("local-dir", true, Some("/x"), None, 7), true);
        assert!(!local.active);
        assert_eq!(local.state.word, "not used");
        assert!(local.problem.contains("local-dir"));
    }

    #[test]
    fn s3_retention_and_encryption_read_honestly() {
        let r = s3_row(target("s3", true, Some("/x"), Some("age1abc"), 7), true);
        assert_eq!(r.keep, "newest 7 per site");
        assert_eq!(r.encryption.word, "encrypted (age)");
        assert_eq!(r.age_recipient, "age1abc");
        let r = s3_row(target("s3", true, Some("/x"), Some("  "), 0), true);
        assert_eq!(r.keep, "all kept, never pruned");
        assert_eq!(r.encryption.cls, "warn");
        assert_eq!(r.keep_n, 0);
    }

    #[test]
    fn the_offsite_pill_counts_what_takes_a_copy() {
        assert_eq!(offsite_pill(0, true, false).cls, "warn");
        assert_eq!(offsite_pill(0, false, false).word, "unknown");
        assert_eq!(offsite_pill(1, true, false).word, "1 in use");
        assert_eq!(offsite_pill(3, false, false).word, "3 in use");
        // No archives are made at all: targets being on changes nothing.
        assert_eq!(offsite_pill(2, true, true).cls, "warn");
    }

    #[test]
    fn card_pills_say_the_state_in_words() {
        assert_eq!(protection_pill("both").word, "archives and snapshots");
        assert_eq!(protection_pill("").word, "archives and snapshots");
        assert_eq!(protection_pill("snapshots").cls, "warn");
        assert_eq!(protection_pill("backups").word, "archives only");

        let b = |drop, keep| BackupConfigView {
            drop_local_after_offsite: drop,
            keep_local_latest: keep,
        };
        assert_eq!(local_copies_pill(&b(false, 3)).word, "kept");
        assert_eq!(local_copies_pill(&b(true, 0)).word, "deleted once off-site");
        assert_eq!(local_copies_pill(&b(true, 2)).word, "newest 2 kept");

        assert_eq!(retention_pill(30, 3, false).word, "30 days · newest 3 kept");
        assert_eq!(retention_pill(1, 1, false).word, "1 day · newest 1 kept");
        assert_eq!(retention_pill(30, 3, true).word, "no archives made");
        assert_eq!(trash_pill(false, 30).word, "off");
        assert_eq!(trash_pill(true, 30).word, "on · 30 days");
        assert_eq!(trash_pill(true, 1).word, "on · 1 day");
    }

    fn render(can_edit: bool, can_targets: bool, s3: Vec<S3Row>, ftp: FtpRow) -> String {
        let config = AgentConfigView::default();
        let active_targets = usize::from(ftp.active) + s3.iter().filter(|r| r.active).count();
        BackupsTpl {
            username: "kevin",
            user_initial: 'K',
            active: "settings",
            css_version: "x",
            htmx_version: "x",
            chrome: Chrome {
                section: "backups",
                title: "Backups",
                lead: "",
                can_edit,
                has_nodes: true,
                flash: None,
                flash_error: None,
            },
            csrf_token: "tok".into(),
            offsite: offsite_pill(active_targets, true, false),
            protection: protection_pill("both"),
            local: local_copies_pill(&config.backup),
            retention: retention_pill(30, 3, false),
            trash: trash_pill(false, 30),
            active_targets,
            snapshots_only: false,
            ftp,
            s3,
            targets_error: None,
            config,
            config_error: None,
            can_targets,
            config_hidden: false,
            s3_hidden: 0,
            can_backfill: can_targets,
            auto_probe_backup_remote: false,
        }
        .render()
        .expect("renders")
    }

    /// An Administrator holds BackupTargets but is not an Owner: the S3
    /// targets stay usable while the FTP form (agent.toml) is read-only.
    #[test]
    fn an_administrator_edits_s3_but_not_the_ftp_target() {
        let html = render(
            false,
            true,
            vec![s3_row(
                target("s3", true, Some("/x"), Some("age1k"), 7),
                true,
            )],
            ftp_row(&remote(true, "sftp", "h", "u", "/b")),
        );
        assert!(
            html.contains(r#"<fieldset class="group" disabled>"#),
            "agent.toml groups read-only"
        );
        assert!(
            html.contains(r#"<fieldset style="border:0;padding:0;margin:0;min-width:0" disabled>"#)
        );
        // The Off-site group itself is open to them.
        let offsite = html.find("Off-site copies").expect("group");
        let open = html[..offsite].rfind("<fieldset").expect("its fieldset");
        assert!(
            !html[open..offsite].contains("disabled"),
            "{}",
            &html[open..offsite]
        );
        assert!(html.contains(r#"class="btn small ghost" data-s3-edit"#));
        assert!(html.contains(r#"data-enabled="true""#));
        assert!(html.contains(r#"action="/settings/backups/7/delete""#));
    }

    /// Somebody with Settings but without the targets right sees the targets
    /// without the edit data (the access key id) or the delete form.
    #[test]
    fn without_the_targets_right_the_rows_carry_no_edit_data() {
        let html = render(
            false,
            false,
            vec![s3_row(target("s3", true, Some("/x"), None, 7), true)],
            ftp_row(&remote(false, "ftp", "", "", "")),
        );
        assert!(!html.contains(r#"class="btn small ghost" data-s3-edit"#));
        assert!(!html.contains("data-access-key-id"));
        assert!(!html.contains("/settings/backups/7/delete"));
        assert!(html.contains("wasabi-eu"), "the row itself is still listed");
    }

    #[test]
    fn nothing_off_site_says_so_and_points_at_both_forms() {
        let html = render(
            true,
            true,
            Vec::new(),
            ftp_row(&remote(false, "ftp", "", "", "")),
        );
        assert!(html.contains("Nothing is copied off-site"));
        assert!(html.contains(r##"href="#offsite-ftp""##));
        assert!(html.contains(r##"href="#offsite-s3""##));
        assert!(!html.contains("<table"), "no empty table");
        if let Ok(dir) = std::env::var("BACKUPS_PAGE_DUMP") {
            let full = render(
                true,
                true,
                vec![
                    s3_row(target("s3", true, Some("/x"), Some("age1k"), 7), true),
                    s3_row(target("s3", true, None, None, 0), false),
                ],
                ftp_row(&remote(true, "sftp", "backup.example", "hyp", "/srv")),
            );
            std::fs::write(format!("{dir}/backups_full.html"), full).expect("dump");
            std::fs::write(format!("{dir}/backups_empty.html"), html).expect("dump");
        }
    }
}
