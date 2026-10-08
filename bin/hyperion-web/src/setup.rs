//! Setup mode: the first-run wizard's state, its one-time setup code, and the
//! gate that keeps everything else shut until an administrator exists.
//!
//! # Why a code at all
//!
//! The installer leaves the panel listening on a public address with no
//! account in it. Whoever reaches the wizard first creates the administrator
//! — so the wizard must not open for "whoever reaches it first". The installer
//! prints a code next to the link, on the terminal of the person who ran it;
//! only that code opens the admin step. Lose it and `hyperion setup-link`
//! prints a new one, which needs root on the box.
//!
//! # State
//!
//! `/var/lib/hyperion/setup.json` (0600). No file means "not in setup mode",
//! which is every install that predates the wizard — none of this applies to
//! them. Only the SHA-256 of the code is stored, and exchanging the code
//! clears it: one use.
//!
//! The file is re-read whenever the code is checked, so `setup-link`, run as
//! root while the service is up, takes effect immediately. The two flags the
//! gate needs on every request are cached in memory.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

/// How long a setup code stays valid.
pub const CODE_TTL_SECS: i64 = 24 * 3600;
/// How long a domain hand-off token stays valid.
pub const HANDOFF_TTL_SECS: i64 = 60;

/// 32 symbols, no I/O/0/1 — a code is read off a terminal and typed by hand.
const CODE_ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
/// 16 symbols × 5 bits = 80 bits, behind a 24 h expiry and the login throttle.
const CODE_LEN: usize = 16;

pub const STATE_PENDING: &str = "pending";
pub const STATE_COMPLETED: &str = "completed";

/// A wizard step. The order of [`Step::ALL`] is the order the wizard walks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    Access,
    Admin,
    TwoFactor,
    Stack,
    System,
    Domain,
    Mail,
    Backups,
    Review,
}

impl Step {
    pub const ALL: [Step; 9] = [
        Step::Access,
        Step::Admin,
        Step::TwoFactor,
        Step::Stack,
        Step::System,
        Step::Domain,
        Step::Mail,
        Step::Backups,
        Step::Review,
    ];

    /// URL segment and the id stored in `steps_done`.
    pub fn id(self) -> &'static str {
        match self {
            Step::Access => "access",
            Step::Admin => "admin",
            Step::TwoFactor => "2fa",
            Step::Stack => "stack",
            Step::System => "system",
            Step::Domain => "domain",
            Step::Mail => "mail",
            Step::Backups => "backups",
            Step::Review => "review",
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Step::Access => "Access",
            Step::Admin => "Admin account",
            Step::TwoFactor => "Two-factor sign-in",
            Step::Stack => "Server software",
            Step::System => "Server identity",
            Step::Domain => "Panel address",
            Step::Mail => "Outgoing mail",
            Step::Backups => "Backups",
            Step::Review => "Review",
        }
    }

    /// Can be left for later without blocking "Open the panel".
    pub fn optional(self) -> bool {
        matches!(self, Step::Domain | Step::Mail | Step::Backups)
    }

    pub fn from_id(id: &str) -> Option<Step> {
        Step::ALL.iter().copied().find(|s| s.id() == id)
    }

    pub fn number(self) -> usize {
        Step::ALL.iter().position(|s| *s == self).unwrap_or(0) + 1
    }
}

/// `/var/lib/hyperion/setup.json`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SetupFile {
    /// [`STATE_PENDING`] or [`STATE_COMPLETED`].
    pub state: String,
    /// Hex SHA-256 of the current code (normalized); empty once used.
    #[serde(default)]
    pub code_sha256: String,
    #[serde(default)]
    pub code_expires_at: i64,
    #[serde(default)]
    pub created_at: i64,
    #[serde(default)]
    pub completed_at: i64,
    /// Step ids done or deliberately skipped.
    #[serde(default)]
    pub steps_done: Vec<String>,
    /// Steps the operator skipped (a subset of `steps_done`), so the review
    /// can tell "skipped" from "done".
    #[serde(default)]
    pub steps_skipped: Vec<String>,
}

impl SetupFile {
    pub fn is_pending(&self) -> bool {
        self.state == STATE_PENDING
    }

    pub fn is_done(&self, step: Step) -> bool {
        self.steps_done.iter().any(|s| s == step.id())
    }

    pub fn is_skipped(&self, step: Step) -> bool {
        self.steps_skipped.iter().any(|s| s == step.id())
    }

    pub fn mark_done(&mut self, step: Step) {
        if !self.is_done(step) {
            self.steps_done.push(step.id().to_string());
        }
        self.steps_skipped.retain(|s| s != step.id());
    }

    pub fn mark_skipped(&mut self, step: Step) {
        self.mark_done(step);
        self.steps_skipped.push(step.id().to_string());
    }

    /// The first step not yet done; Review once everything else is.
    pub fn next_step(&self) -> Step {
        Step::ALL
            .iter()
            .copied()
            .find(|s| *s != Step::Review && !self.is_done(*s))
            .unwrap_or(Step::Review)
    }
}

pub fn load_file(path: &Path) -> std::io::Result<Option<SetupFile>> {
    match std::fs::read(path) {
        Ok(b) => serde_json::from_slice(&b)
            .map(Some)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

pub fn save_file(path: &Path, f: &SetupFile) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let bytes = serde_json::to_vec_pretty(f)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// A fresh code, `XXXX-XXXX-XXXX-XXXX`.
pub fn mint_code() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let raw: String = (0..CODE_LEN)
        .map(|_| CODE_ALPHABET[rng.gen_range(0..CODE_ALPHABET.len())] as char)
        .collect();
    raw.as_bytes()
        .chunks(4)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join("-")
}

/// What people type: any case, with or without dashes and spaces.
pub fn normalize_code(input: &str) -> String {
    input
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

pub fn hash_code(code: &str) -> String {
    hex::encode(Sha256::digest(normalize_code(code).as_bytes()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeCheck {
    Ok,
    Wrong,
    Expired,
    /// No code outstanding: already used, or setup not pending.
    NoneIssued,
}

pub fn check_code(f: &SetupFile, input: &str, now: i64) -> CodeCheck {
    use subtle::ConstantTimeEq;
    if !f.is_pending() || f.code_sha256.is_empty() {
        return CodeCheck::NoneIssued;
    }
    let given = hash_code(input);
    let ok: bool = given.as_bytes().ct_eq(f.code_sha256.as_bytes()).into();
    if !ok {
        return CodeCheck::Wrong;
    }
    if now >= f.code_expires_at {
        return CodeCheck::Expired;
    }
    CodeCheck::Ok
}

/// Who a domain hand-off logs in.
#[derive(Debug, Clone)]
pub struct Handoff {
    pub user_id: i64,
    pub username: String,
    pub role: String,
    pub expires_at: i64,
}

/// Runtime handle on setup mode, held in `AppState`.
pub struct SetupCtl {
    path: PathBuf,
    active: AtomicBool,
    admin_created: AtomicBool,
    write_lock: std::sync::Mutex<()>,
    handoffs: std::sync::Mutex<HashMap<String, Handoff>>,
}

impl SetupCtl {
    /// Read the state file once at startup. An unreadable file is logged and
    /// treated as "not in setup mode": failing open here means an existing
    /// panel keeps working; it cannot open the wizard to anyone, because the
    /// wizard needs a code that only a readable file can hold.
    pub fn load(path: PathBuf) -> Self {
        let file = match load_file(&path) {
            Ok(f) => f,
            Err(e) => {
                tracing::error!(path=%path.display(), error=%e, "setup state unreadable — setup mode off");
                None
            }
        };
        let ctl = Self::inactive(path);
        if let Some(f) = file {
            ctl.refresh_flags(&f);
        }
        ctl
    }

    /// Not in setup mode (tests, and every pre-wizard install).
    pub fn inactive(path: PathBuf) -> Self {
        Self {
            path,
            active: AtomicBool::new(false),
            admin_created: AtomicBool::new(false),
            write_lock: std::sync::Mutex::new(()),
            handoffs: std::sync::Mutex::new(HashMap::new()),
        }
    }

    fn refresh_flags(&self, f: &SetupFile) {
        self.active.store(f.is_pending(), Ordering::Relaxed);
        self.admin_created
            .store(f.is_done(Step::Admin), Ordering::Relaxed);
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Setup is pending.
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Relaxed)
    }

    /// The wizard has created its administrator.
    pub fn admin_created(&self) -> bool {
        self.admin_created.load(Ordering::Relaxed)
    }

    /// The file as it is on disk now.
    pub fn read(&self) -> Option<SetupFile> {
        match load_file(&self.path) {
            Ok(f) => f,
            Err(e) => {
                tracing::error!(error=%e, "setup state unreadable");
                None
            }
        }
    }

    /// Read-modify-write under a lock, then refresh the cached flags.
    pub fn update<R>(&self, f: impl FnOnce(&mut SetupFile) -> R) -> std::io::Result<R> {
        let _g = self.write_lock.lock().unwrap_or_else(|p| p.into_inner());
        let mut file = load_file(&self.path)?.unwrap_or_default();
        let r = f(&mut file);
        save_file(&self.path, &file)?;
        self.refresh_flags(&file);
        Ok(r)
    }

    /// Check a code and, when it is right, use it up.
    pub fn consume_code(&self, input: &str, now: i64) -> std::io::Result<CodeCheck> {
        self.update(|f| {
            let r = check_code(f, input, now);
            if r == CodeCheck::Ok {
                f.code_sha256.clear();
                f.mark_done(Step::Access);
            }
            r
        })
    }

    /// A single-use token that logs `h` in on another origin.
    pub fn issue_handoff(&self, h: Handoff) -> String {
        use rand::RngCore;
        let mut b = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut b);
        let token = hex::encode(b);
        let mut m = self.handoffs.lock().unwrap_or_else(|p| p.into_inner());
        let now = hyperion_types::now_secs();
        m.retain(|_, v| v.expires_at > now);
        m.insert(token.clone(), h);
        token
    }

    pub fn take_handoff(&self, token: &str, now: i64) -> Option<Handoff> {
        let mut m = self.handoffs.lock().unwrap_or_else(|p| p.into_inner());
        let h = m.remove(token)?;
        (h.expires_at > now).then_some(h)
    }
}

/// Start (or restart) setup with a fresh code. Keeps the steps already done,
/// so a new link mid-wizard resumes where it left off. Refuses a completed
/// setup.
pub fn issue_code(path: &Path, now: i64) -> std::io::Result<Result<String, &'static str>> {
    let mut f = load_file(path)?.unwrap_or_default();
    if f.state == STATE_COMPLETED {
        return Ok(Err("setup is already finished"));
    }
    let code = mint_code();
    f.state = STATE_PENDING.into();
    if f.created_at == 0 {
        f.created_at = now;
    }
    f.code_sha256 = hash_code(&code);
    f.code_expires_at = now + CODE_TTL_SECS;
    save_file(path, &f)?;
    Ok(Ok(code))
}

/// Paths that stay reachable while no administrator exists.
pub fn path_open_during_setup(path: &str) -> bool {
    path == "/setup"
        || path.starts_with("/setup/")
        || path.starts_with("/static/")
        || path == "/healthz"
        || path == "/readyz"
}

/// Middleware: while setup is pending, send everything to the wizard until
/// the administrator exists; after that, only the dashboard is bounced back
/// to it (normal sign-in applies everywhere else).
pub async fn setup_gate(
    axum::extract::State(state): axum::extract::State<crate::state::SharedState>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    if !state.setup.is_active() {
        return next.run(req).await;
    }
    let path = req.uri().path();
    if path_open_during_setup(path) {
        return next.run(req).await;
    }
    if !state.setup.admin_created() || path == "/" {
        return axum::response::Redirect::to("/setup").into_response();
    }
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_look_right() {
        let c = mint_code();
        assert_eq!(c.len(), 19);
        assert_eq!(c.matches('-').count(), 3);
        assert!(normalize_code(&c)
            .bytes()
            .all(|b| CODE_ALPHABET.contains(&b)));
        assert_ne!(mint_code(), mint_code());
    }

    #[test]
    fn typing_variations_match() {
        let f = SetupFile {
            state: STATE_PENDING.into(),
            code_sha256: hash_code("K7QM-4XWD-9HPR-T2NV"),
            code_expires_at: 100,
            ..Default::default()
        };
        assert_eq!(check_code(&f, "K7QM-4XWD-9HPR-T2NV", 50), CodeCheck::Ok);
        assert_eq!(check_code(&f, "k7qm 4xwd 9hpr t2nv", 50), CodeCheck::Ok);
        assert_eq!(check_code(&f, "K7QM4XWD9HPRT2NV", 50), CodeCheck::Ok);
        assert_eq!(check_code(&f, "K7QM-4XWD-9HPR-T2NW", 50), CodeCheck::Wrong);
        assert_eq!(check_code(&f, "", 50), CodeCheck::Wrong);
        assert_eq!(
            check_code(&f, "K7QM-4XWD-9HPR-T2NV", 100),
            CodeCheck::Expired
        );
    }

    #[test]
    fn used_or_finished_setup_has_no_code() {
        let mut f = SetupFile {
            state: STATE_PENDING.into(),
            code_sha256: String::new(),
            code_expires_at: 100,
            ..Default::default()
        };
        assert_eq!(check_code(&f, "anything", 1), CodeCheck::NoneIssued);
        f.code_sha256 = hash_code("ABCD");
        f.state = STATE_COMPLETED.into();
        assert_eq!(check_code(&f, "ABCD", 1), CodeCheck::NoneIssued);
    }

    #[test]
    fn code_is_single_use() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("setup.json");
        let code = issue_code(&p, 1000).unwrap().unwrap();
        let ctl = SetupCtl::load(p.clone());
        assert!(ctl.is_active());
        assert!(!ctl.admin_created());
        assert_eq!(ctl.consume_code(&code, 1001).unwrap(), CodeCheck::Ok);
        assert_eq!(
            ctl.consume_code(&code, 1002).unwrap(),
            CodeCheck::NoneIssued
        );
        let f = load_file(&p).unwrap().unwrap();
        assert!(f.code_sha256.is_empty());
        assert!(f.is_done(Step::Access));
    }

    #[test]
    fn new_code_keeps_progress_and_refuses_finished_setup() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("setup.json");
        issue_code(&p, 1000).unwrap().unwrap();
        let ctl = SetupCtl::load(p.clone());
        ctl.update(|f| f.mark_done(Step::Admin)).unwrap();
        assert!(ctl.admin_created());
        issue_code(&p, 2000).unwrap().unwrap();
        let f = load_file(&p).unwrap().unwrap();
        assert!(f.is_done(Step::Admin));
        assert_eq!(f.created_at, 1000);
        ctl.update(|f| f.state = STATE_COMPLETED.into()).unwrap();
        assert!(!ctl.is_active());
        assert!(issue_code(&p, 3000).unwrap().is_err());
    }

    #[test]
    fn no_file_means_no_setup_mode() {
        let dir = tempfile::tempdir().unwrap();
        let ctl = SetupCtl::load(dir.path().join("absent.json"));
        assert!(!ctl.is_active());
    }

    #[test]
    fn state_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("setup.json");
        issue_code(&p, 1).unwrap().unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn next_step_walks_in_order_and_skips_count() {
        let mut f = SetupFile {
            state: STATE_PENDING.into(),
            ..Default::default()
        };
        assert_eq!(f.next_step(), Step::Access);
        for s in [
            Step::Access,
            Step::Admin,
            Step::TwoFactor,
            Step::Stack,
            Step::System,
        ] {
            f.mark_done(s);
        }
        assert_eq!(f.next_step(), Step::Domain);
        f.mark_skipped(Step::Domain);
        assert!(f.is_skipped(Step::Domain));
        assert_eq!(f.next_step(), Step::Mail);
        f.mark_done(Step::Mail);
        f.mark_done(Step::Backups);
        assert_eq!(f.next_step(), Step::Review);
        // Doing a skipped step later clears the "skipped" mark.
        f.mark_done(Step::Domain);
        assert!(!f.is_skipped(Step::Domain));
    }

    #[test]
    fn handoff_is_single_use_and_expires() {
        let ctl = SetupCtl::inactive(PathBuf::from("/nonexistent"));
        let now = hyperion_types::now_secs();
        let h = Handoff {
            user_id: 7,
            username: "kevin".into(),
            role: "super_admin".into(),
            expires_at: now + 60,
        };
        let t = ctl.issue_handoff(h.clone());
        assert_eq!(ctl.take_handoff(&t, now).map(|h| h.user_id), Some(7));
        assert!(ctl.take_handoff(&t, now).is_none());
        let t2 = ctl.issue_handoff(h);
        assert!(ctl.take_handoff(&t2, now + 61).is_none());
    }

    #[test]
    fn gate_paths() {
        assert!(path_open_during_setup("/setup"));
        assert!(path_open_during_setup("/setup/admin"));
        assert!(path_open_during_setup("/static/app.css"));
        assert!(path_open_during_setup("/healthz"));
        assert!(!path_open_during_setup("/setupx"));
        assert!(!path_open_during_setup("/login"));
        assert!(!path_open_during_setup("/api/enroll"));
        assert!(!path_open_during_setup("/"));
    }
}
