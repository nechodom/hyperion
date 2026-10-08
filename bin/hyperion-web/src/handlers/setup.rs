//! The first-run setup wizard (`/setup/*`). See `crate::setup` for the state
//! file, the setup code and the gate; this module is the pages.
//!
//! # Who may do what
//!
//! * **Access, Admin account** — before any account exists. The person proves
//!   they ran the installer by entering the setup code; that buys a signed
//!   setup cookie (`<session cookie>_setup`) good for these two steps only.
//!   It is never a session: nothing else in the panel reads it.
//! * **Two-factor** — the new administrator's own session, still gated into
//!   enrolment (`enforce_admin_2fa` is on by default).
//! * **Everything after** — a full super_admin session.
//!
//! These routes sit outside the `require_auth` / `check_csrf` layers (the
//! first two steps have no session to check), so each POST verifies its own
//! CSRF token against whichever identity it runs under.

use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::handlers::login;
use crate::setup::{CodeCheck, Handoff, SetupFile, Step};
use crate::state::SharedState;
use askama::Template;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Form;
use hyperion_auth::Session;
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use serde::Deserialize;
use std::net::SocketAddr;

/// `purpose` of the setup cookie. Not a session purpose, so
/// `Session::is_real_session` is false for it everywhere else.
const SETUP_PURPOSE: &str = "setup_access";
/// Minimum administrator password length.
const MIN_PASSWORD_LEN: usize = 12;

// ───────────────────────── page frame ─────────────────────────

pub struct RailItem {
    pub number: usize,
    pub name: &'static str,
    pub done: bool,
    pub skipped: bool,
    pub current: bool,
    pub optional: bool,
    /// Where clicking it goes; `None` = not a link (the pre-account steps,
    /// and anything not reached yet).
    pub href: Option<String>,
}

pub struct Frame {
    pub rail: Vec<RailItem>,
    pub step_no: usize,
    pub step_total: usize,
    pub optional: bool,
    pub css_version: &'static str,
    pub htmx_version: &'static str,
    pub csrf: String,
    pub error: Option<String>,
    pub notice: Option<String>,
}

fn frame(file: &SetupFile, current: Step, csrf: String) -> Frame {
    let admin_done = file.is_done(Step::Admin);
    let rail = Step::ALL
        .iter()
        .map(|&s| {
            let done = file.is_done(s);
            let reachable = admin_done
                && !matches!(s, Step::Access | Step::Admin)
                && (done || s == file.next_step() || s == current);
            RailItem {
                number: s.number(),
                name: s.name(),
                done,
                skipped: file.is_skipped(s),
                current: s == current,
                optional: s.optional(),
                href: reachable.then(|| format!("/setup/{}", s.id())),
            }
        })
        .collect();
    Frame {
        rail,
        step_no: current.number(),
        step_total: Step::ALL.len(),
        optional: current.optional(),
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        csrf,
        error: None,
        notice: None,
    }
}

// ───────────────────────── identities ─────────────────────────

fn setup_cookie_name(state: &SharedState) -> String {
    format!("{}_setup", state.cookie_name())
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(';'))
        .map(str::trim)
        .find_map(|kv| {
            let (k, v) = kv.split_once('=')?;
            (k == name).then(|| v.to_string())
        })
}

/// The setup cookie, if present, valid and of the right purpose.
fn setup_session(state: &SharedState, headers: &HeaderMap) -> Option<Session> {
    let token = cookie_value(headers, &setup_cookie_name(state))?;
    let s = state
        .session
        .verify(&token, hyperion_types::now_secs())
        .ok()?;
    (s.purpose == SETUP_PURPOSE).then_some(s)
}

fn setup_cookie_header(state: &SharedState, token: &str, max_age: i64) -> HeaderValue {
    let mut s = format!(
        "{}={}; Path=/setup; HttpOnly; SameSite=Strict; Max-Age={max_age}",
        setup_cookie_name(state),
        token
    );
    if state.secure_cookies() {
        s.push_str("; Secure");
    }
    HeaderValue::from_str(&s).unwrap_or(HeaderValue::from_static(""))
}

fn mint_csrf(state: &SharedState, sid: &str) -> String {
    hyperion_auth::csrf::mint(
        state.csrf_key.as_ref(),
        sid,
        hyperion_auth::csrf::SESSION_WIDE_FORM_ID,
        hyperion_types::now_secs(),
    )
}

fn csrf_ok(state: &SharedState, sid: &str, token: &str) -> bool {
    !sid.is_empty()
        && hyperion_auth::csrf::verify(
            state.csrf_key.as_ref(),
            sid,
            hyperion_auth::csrf::SESSION_WIDE_FORM_ID,
            token,
            hyperion_types::now_secs(),
        )
}

/// The wizard's administrator, or where to send whoever this is instead.
/// `allow_2fa_pending` is true only for the two-factor step itself.
// The Err is the response itself, returned straight from the handler; boxing
// it would only add an unwrap at every one of the twenty call sites.
#[allow(clippy::result_large_err)]
fn wizard_admin(ctx: &AuthCtx, here: &str, allow_2fa_pending: bool) -> Result<Session, Response> {
    let login = || {
        let next: String = url::form_urlencoded::byte_serialize(here.as_bytes()).collect();
        Redirect::to(&format!("/login?next={next}")).into_response()
    };
    let Some(s) = ctx.session.clone() else {
        return Err(login());
    };
    if !s.is_real_session() {
        return Err(login());
    }
    if s.needs_2fa_enrollment() && !allow_2fa_pending {
        return Err(Redirect::to("/setup/2fa").into_response());
    }
    if !ctx.is_super_admin() {
        return Err(AppError::Forbidden.into_response());
    }
    Ok(s)
}

/// Setup must be pending for any of this to exist.
fn ensure_active(state: &SharedState) -> Result<SetupFile, AppError> {
    if !state.setup.is_active() {
        return Err(AppError::NotFound);
    }
    state
        .setup
        .read()
        .filter(|f| f.is_pending())
        .ok_or(AppError::NotFound)
}

fn mark(state: &SharedState, step: Step, skipped: bool) -> Result<(), AppError> {
    state
        .setup
        .update(|f| {
            if skipped {
                f.mark_skipped(step)
            } else {
                f.mark_done(step)
            }
        })
        .map_err(|e| AppError::Internal(format!("save setup state: {e}")))
}

fn go(step: Step) -> Response {
    Redirect::to(&format!("/setup/{}", step.id())).into_response()
}

async fn rpc(state: &SharedState, req: Request) -> Result<RpcResponse, AppError> {
    hyperion_rpc_client::call(&state.agent_socket, req)
        .await
        .map_err(AppError::from)
}

async fn admin_user(state: &SharedState, id: i64) -> Option<hyperion_types::WebUserSummary> {
    match rpc(state, Request::WebUserGet { id }).await {
        Ok(RpcResponse::WebUserGet(u)) => u,
        _ => None,
    }
}

// ───────────────────────── /setup ─────────────────────────

#[derive(Deserialize, Default)]
pub struct CodeQuery {
    #[serde(default)]
    t: Option<String>,
}

/// GET /setup — wherever the wizard stands. The installer's link lands here
/// with the code in `?t=`.
pub async fn get_root(
    State(state): State<SharedState>,
    headers: HeaderMap,
    ctx: AuthCtx,
    Query(q): Query<CodeQuery>,
) -> Result<Response, AppError> {
    let file = ensure_active(&state)?;
    if !file.is_done(Step::Admin) {
        if setup_session(&state, &headers).is_some() {
            return Ok(go(Step::Admin));
        }
        let to = match q.t.as_deref().map(crate::setup::normalize_code) {
            Some(c) if !c.is_empty() && c.len() <= 32 => format!("/setup/access?t={c}"),
            _ => "/setup/access".to_string(),
        };
        return Ok(Redirect::to(&to).into_response());
    }
    if let Err(r) = wizard_admin(&ctx, "/setup", true) {
        return Ok(r);
    }
    Ok(go(file.next_step()))
}

// ───────────────────────── 1. Access ─────────────────────────

#[derive(Template)]
#[template(path = "setup_access.html")]
struct AccessTpl {
    f: Frame,
    code: String,
}

/// Show the code as XXXX-XXXX-XXXX-XXXX however it arrived.
fn pretty_code(raw: &str) -> String {
    let n = crate::setup::normalize_code(raw);
    n.as_bytes()
        .chunks(4)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join("-")
}

pub async fn get_access(
    State(state): State<SharedState>,
    Query(q): Query<CodeQuery>,
) -> Result<Response, AppError> {
    let file = ensure_active(&state)?;
    if file.is_done(Step::Admin) {
        return Ok(Redirect::to("/setup").into_response());
    }
    let code =
        q.t.as_deref()
            .filter(|t| t.len() <= 40)
            .map(pretty_code)
            .unwrap_or_default();
    let tpl = AccessTpl {
        f: frame(&file, Step::Access, String::new()),
        code,
    };
    Ok(Html(tpl.render()?).into_response())
}

#[derive(Deserialize)]
pub struct AccessForm {
    code: String,
}

pub async fn post_access(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Form(form): Form<AccessForm>,
) -> Result<Response, AppError> {
    let file = ensure_active(&state)?;
    if file.is_done(Step::Admin) {
        return Ok(Redirect::to("/setup").into_response());
    }
    let render = |msg: String, status: StatusCode| -> Result<Response, AppError> {
        let mut f = frame(&file, Step::Access, String::new());
        f.error = Some(msg);
        let tpl = AccessTpl {
            f,
            code: pretty_code(&form.code),
        };
        Ok((status, Html(tpl.render()?)).into_response())
    };
    // Same per-peer bucket as the sign-in form: a setup code is a credential.
    let tkey = login::throttle_key(peer);
    if let Some(wait) = login::throttle_wait(&tkey) {
        let m = login::wait_minutes(wait);
        return render(
            format!(
                "Too many wrong codes from this address. Try again in {m} minute{}.",
                if m == 1 { "" } else { "s" }
            ),
            StatusCode::TOO_MANY_REQUESTS,
        );
    }
    let now = hyperion_types::now_secs();
    let check = state
        .setup
        .consume_code(&form.code, now)
        .map_err(|e| AppError::Internal(format!("setup state: {e}")))?;
    match check {
        CodeCheck::Ok => {
            login::clear_throttle(&tkey);
            let s = Session {
                sid: format!("setup-{}", ulid::Ulid::new()),
                user_id: 0,
                created_at: now,
                expires_at: now + crate::setup::CODE_TTL_SECS,
                username: String::new(),
                role: String::new(),
                purpose: SETUP_PURPOSE.to_string(),
                caps: 0,
                scope_all: false,
                caps_present: false,
            };
            let token = state
                .session
                .sign(&s)
                .map_err(|e| AppError::Internal(e.to_string()))?;
            let mut resp = go(Step::Admin);
            resp.headers_mut().insert(
                header::SET_COOKIE,
                setup_cookie_header(&state, &token, crate::setup::CODE_TTL_SECS),
            );
            Ok(resp)
        }
        CodeCheck::Wrong => {
            login::record_failure(&tkey);
            render(
                "That code doesn't match. Copy it again from the installer's output — \
                 letters and digits only, dashes are optional."
                    .into(),
                StatusCode::UNPROCESSABLE_ENTITY,
            )
        }
        CodeCheck::Expired => render(
            "This code has expired. Run `hyperion setup-link` on the server for a new one.".into(),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        CodeCheck::NoneIssued => render(
            "This code has already been used. If that wasn't you, run `hyperion setup-link` \
             on the server for a new one."
                .into(),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
    }
}

// ───────────────────────── 2. Admin account ─────────────────────────

#[derive(Template)]
#[template(path = "setup_admin.html")]
struct AdminTpl {
    f: Frame,
    username: String,
    email: String,
    min_len: usize,
}

pub async fn get_admin(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let file = ensure_active(&state)?;
    if file.is_done(Step::Admin) {
        return Ok(Redirect::to("/setup").into_response());
    }
    let Some(s) = setup_session(&state, &headers) else {
        return Ok(go(Step::Access));
    };
    let tpl = AdminTpl {
        f: frame(&file, Step::Admin, mint_csrf(&state, &s.sid)),
        username: "admin".into(),
        email: String::new(),
        min_len: MIN_PASSWORD_LEN,
    };
    Ok(Html(tpl.render()?).into_response())
}

#[derive(Deserialize)]
pub struct AdminForm {
    username: String,
    email: String,
    password: String,
    password2: String,
    #[serde(default)]
    _csrf: String,
}

/// What is wrong with the account form, in the words the page shows.
pub(crate) fn admin_form_problem(
    username: &str,
    email: &str,
    password: &str,
    password2: &str,
) -> Option<String> {
    let u = username.trim();
    if u.is_empty() || u.len() > 64 {
        return Some("Choose a username of 1 to 64 characters.".into());
    }
    if !u
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '@'))
    {
        return Some("Use only letters, digits and . _ - @ in the username.".into());
    }
    let e = email.trim();
    let (local, domain) = e.split_once('@').unwrap_or(("", ""));
    if local.is_empty() || !domain.contains('.') || e.len() > 254 || e.contains(char::is_whitespace)
    {
        return Some(
            "Enter an email address you read — password resets and alerts go there.".into(),
        );
    }
    if password.chars().count() < MIN_PASSWORD_LEN {
        return Some(format!(
            "Use a password of at least {MIN_PASSWORD_LEN} characters."
        ));
    }
    if password != password2 {
        return Some("The two passwords don't match.".into());
    }
    None
}

pub async fn post_admin(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Form(form): Form<AdminForm>,
) -> Result<Response, AppError> {
    let file = ensure_active(&state)?;
    if file.is_done(Step::Admin) {
        return Ok(Redirect::to("/setup").into_response());
    }
    let Some(s) = setup_session(&state, &headers) else {
        return Ok(go(Step::Access));
    };
    if !csrf_ok(&state, &s.sid, &form._csrf) {
        return Err(AppError::Forbidden);
    }
    let rerender = |msg: String| -> Result<Response, AppError> {
        let mut f = frame(&file, Step::Admin, mint_csrf(&state, &s.sid));
        f.error = Some(msg);
        let tpl = AdminTpl {
            f,
            username: form.username.trim().to_string(),
            email: form.email.trim().to_string(),
            min_len: MIN_PASSWORD_LEN,
        };
        Ok((StatusCode::UNPROCESSABLE_ENTITY, Html(tpl.render()?)).into_response())
    };
    if let Some(msg) =
        admin_form_problem(&form.username, &form.email, &form.password, &form.password2)
    {
        return rerender(msg);
    }
    // Someone else finished this step a moment ago (two tabs, two people
    // with the same code before it was used): never create a second owner.
    if let Ok(RpcResponse::WebUserList(users)) = rpc(&state, Request::WebUserList).await {
        if !users.is_empty() {
            let _ = mark(&state, Step::Admin, false);
            return Ok(Redirect::to("/login?next=%2Fsetup").into_response());
        }
    }
    let username = form.username.trim().to_string();
    let id = match rpc(
        &state,
        Request::WebUserCreate {
            username: username.clone(),
            email: form.email.trim().to_string(),
            password: form.password.clone(),
            role: "super_admin".into(),
        },
    )
    .await?
    {
        RpcResponse::WebUserCreate { id } => id,
        RpcResponse::Error(e) => return rerender(e.to_string()),
        _ => return Err(AppError::Internal("unexpected response".into())),
    };
    mark(&state, Step::Admin, false)?;
    let purpose = if state.enforce_admin_2fa() {
        hyperion_auth::PURPOSE_SESSION_2FA_PENDING
    } else {
        hyperion_auth::PURPOSE_SESSION
    };
    let mut resp = login::mint_session_redirect(
        &state,
        id,
        username,
        "super_admin".into(),
        "/setup/2fa",
        &headers,
        purpose,
        true,
    )
    .await?;
    // mint_session_redirect sends a 2FA-pending admin to the profile's
    // enrolment card; the wizard has its own step for that.
    resp.headers_mut()
        .insert(header::LOCATION, HeaderValue::from_static("/setup/2fa"));
    // The setup cookie has done its job.
    resp.headers_mut()
        .append(header::SET_COOKIE, setup_cookie_header(&state, "", 0));
    Ok(resp)
}

// ───────────────────────── 3. Two-factor ─────────────────────────

#[derive(Template)]
#[template(path = "setup_2fa.html")]
struct TwoFaTpl {
    f: Frame,
    qr_svg: String,
    secret: String,
    otpauth: String,
    codes: Vec<String>,
    codes_joined: String,
    can_skip: bool,
}

fn qr_svg(otpauth: &str) -> String {
    use qrcode::render::svg;
    match qrcode::QrCode::new(otpauth.as_bytes()) {
        Ok(code) => code
            .render::<svg::Color>()
            .min_dimensions(180, 180)
            .max_dimensions(220, 220)
            .light_color(svg::Color("#ffffff"))
            .dark_color(svg::Color("#111111"))
            .build(),
        Err(_) => "<p>QR generation failed — type the key into your app instead.</p>".into(),
    }
}

pub async fn get_2fa(State(state): State<SharedState>, ctx: AuthCtx) -> Result<Response, AppError> {
    let file = ensure_active(&state)?;
    let s = match wizard_admin(&ctx, "/setup/2fa", true) {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    if admin_user(&state, s.user_id)
        .await
        .map(|u| u.totp_enrolled)
        .unwrap_or(false)
    {
        mark(&state, Step::TwoFactor, false)?;
        return Ok(go(Step::Stack));
    }
    let en = match rpc(&state, Request::Web2faEnrollStart { user_id: s.user_id }).await? {
        RpcResponse::Web2faEnrollStart(e) => e,
        RpcResponse::Error(e) => return Err(AppError::Rpc(e.to_string())),
        _ => return Err(AppError::Internal("unexpected response".into())),
    };
    let tpl = TwoFaTpl {
        f: frame(
            &file,
            Step::TwoFactor,
            super::session_csrf_token(&state, &ctx),
        ),
        qr_svg: qr_svg(&en.otpauth_url),
        secret: en.secret_base32,
        otpauth: en.otpauth_url,
        codes_joined: en.backup_codes.join(" "),
        codes: en.backup_codes,
        can_skip: !state.enforce_admin_2fa(),
    };
    Ok(Html(tpl.render()?).into_response())
}

#[derive(Deserialize)]
pub struct TwoFaForm {
    code: String,
    /// Echoed back from the page so a mistyped code re-shows the SAME QR —
    /// starting enrolment again would replace the secret already scanned.
    #[serde(default)]
    secret: String,
    #[serde(default)]
    otpauth: String,
    #[serde(default)]
    codes: String,
    #[serde(default)]
    _csrf: String,
}

pub async fn post_2fa(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<TwoFaForm>,
) -> Result<Response, AppError> {
    let file = ensure_active(&state)?;
    let s = match wizard_admin(&ctx, "/setup/2fa", true) {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    if !csrf_ok(&state, &s.sid, &form._csrf) {
        return Err(AppError::Forbidden);
    }
    let code: String = form.code.chars().filter(|c| !c.is_whitespace()).collect();
    let ok = matches!(
        rpc(
            &state,
            Request::Web2faConfirmEnroll {
                user_id: s.user_id,
                code,
            },
        )
        .await?,
        RpcResponse::Web2faConfirmEnroll { ok: true }
    );
    if !ok {
        let codes: Vec<String> = form.codes.split_whitespace().map(str::to_string).collect();
        let mut f = frame(
            &file,
            Step::TwoFactor,
            super::session_csrf_token(&state, &ctx),
        );
        f.error = Some(
            "That code was not accepted. Check that the phone's clock is right and enter the \
             code that is showing now."
                .into(),
        );
        let tpl = TwoFaTpl {
            f,
            qr_svg: qr_svg(&form.otpauth),
            secret: form.secret,
            otpauth: form.otpauth,
            codes_joined: codes.join(" "),
            codes,
            can_skip: !state.enforce_admin_2fa(),
        };
        return Ok((StatusCode::UNPROCESSABLE_ENTITY, Html(tpl.render()?)).into_response());
    }
    mark(&state, Step::TwoFactor, false)?;
    let mut resp = go(Step::Stack);
    // Lift the enrolment gate on this session, as /profile/2fa/confirm does.
    if s.needs_2fa_enrollment() {
        let now = hyperion_types::now_secs();
        let (caps, scope_all, caps_present) = crate::auth::resolve_caps(&state, s.user_id).await;
        let full = Session {
            sid: s.sid.clone(),
            user_id: s.user_id,
            created_at: now,
            expires_at: now + state.session_ttl(),
            username: s.username.clone(),
            role: s.role.clone(),
            purpose: hyperion_auth::PURPOSE_SESSION.to_string(),
            caps,
            scope_all,
            caps_present,
        };
        if let Ok(token) = state.session.sign(&full) {
            resp.headers_mut()
                .insert(header::SET_COOKIE, crate::auth::set_cookie(&state, &token));
        }
    }
    Ok(resp)
}

// ───────────────────────── skip ─────────────────────────

#[derive(Deserialize)]
pub struct CsrfOnly {
    #[serde(default)]
    _csrf: String,
}

/// POST /setup/skip/:step — leave an optional step for later.
pub async fn post_skip(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Path(step): Path<String>,
    Form(form): Form<CsrfOnly>,
) -> Result<Response, AppError> {
    ensure_active(&state)?;
    let step = Step::from_id(&step).ok_or(AppError::NotFound)?;
    let allowed = step.optional() || (step == Step::TwoFactor && !state.enforce_admin_2fa());
    if !allowed {
        return Err(AppError::BadRequest("this step cannot be skipped".into()));
    }
    let s = match wizard_admin(&ctx, "/setup", step == Step::TwoFactor) {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    if !csrf_ok(&state, &s.sid, &form._csrf) {
        return Err(AppError::Forbidden);
    }
    mark(&state, step, true)?;
    let file = state.setup.read().unwrap_or_default();
    Ok(go(file.next_step()))
}

// ───────────────────────── 4. Server software ─────────────────────────

pub struct ComponentRow {
    pub name: String,
    pub label: String,
    pub state: String,
}

fn component_label(c: &str) -> String {
    match c {
        "mariadb" => "MariaDB".into(),
        "postgresql" => "PostgreSQL".into(),
        "redis" => "Redis".into(),
        "vsftpd" => "FTP (vsftpd)".into(),
        "phpmyadmin" => "phpMyAdmin".into(),
        p if p.starts_with("php") => format!("PHP {} + wp-cli", p.trim_start_matches("php")),
        other => other.into(),
    }
}

#[derive(Template)]
#[template(path = "setup_stack.html")]
struct StackTpl {
    f: Frame,
    /// Show the picker (nothing installed yet, or a retry).
    picking: bool,
    progress: StackProgress,
}

/// The progress block alone, for the poll.
#[derive(Template)]
#[template(path = "_setup_stack_progress.html")]
struct StackPartial {
    progress: StackProgress,
}

pub struct StackProgress {
    pub state: String,
    pub rows: Vec<ComponentRow>,
    pub log_tail: String,
    pub running: bool,
    pub finished: bool,
    pub failed: bool,
    pub elapsed: String,
    pub csrf: String,
}

fn stack_progress(st: hyperion_types::SetupStackStatus, csrf: String) -> StackProgress {
    let now = hyperion_types::now_secs();
    let end = if st.finished_at > 0 {
        st.finished_at
    } else {
        now
    };
    let secs = if st.started_at > 0 {
        (end - st.started_at).max(0)
    } else {
        0
    };
    let failed = matches!(st.state.as_str(), "failed" | "interrupted")
        || st.components.iter().any(|c| c.state == "failed");
    StackProgress {
        running: st.state == "running",
        finished: matches!(st.state.as_str(), "succeeded" | "failed" | "interrupted"),
        failed,
        rows: st
            .components
            .iter()
            .map(|c| ComponentRow {
                name: c.name.clone(),
                label: component_label(&c.name),
                state: c.state.clone(),
            })
            .collect(),
        log_tail: st.log_tail,
        state: st.state,
        elapsed: format!("{} min {:02} s", secs / 60, secs % 60),
        csrf,
    }
}

async fn stack_status(state: &SharedState) -> Result<hyperion_types::SetupStackStatus, AppError> {
    match rpc(state, Request::SetupStackStatus).await? {
        RpcResponse::SetupStackStatus(s) => Ok(s),
        RpcResponse::Error(e) => Err(AppError::Rpc(e.to_string())),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[derive(Deserialize, Default)]
pub struct StackQuery {
    #[serde(default)]
    retry: Option<String>,
}

pub async fn get_stack(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Query(q): Query<StackQuery>,
) -> Result<Response, AppError> {
    let file = ensure_active(&state)?;
    if let Err(r) = wizard_admin(&ctx, "/setup/stack", false) {
        return Ok(r);
    }
    let csrf = super::session_csrf_token(&state, &ctx);
    let st = stack_status(&state).await?;
    let picking = st.state == "idle" || (q.retry.is_some() && st.state != "running");
    let tpl = StackTpl {
        f: frame(&file, Step::Stack, csrf.clone()),
        picking,
        progress: stack_progress(st, csrf),
    };
    Ok(Html(tpl.render()?).into_response())
}

/// GET /setup/stack/status — the progress block, polled every 2 s while the
/// job runs. 286 tells htmx to stop polling once it has finished.
pub async fn get_stack_status(
    State(state): State<SharedState>,
    ctx: AuthCtx,
) -> Result<Response, AppError> {
    ensure_active(&state)?;
    if let Err(r) = wizard_admin(&ctx, "/setup/stack", false) {
        return Ok(r);
    }
    let p = stack_progress(
        stack_status(&state).await?,
        super::session_csrf_token(&state, &ctx),
    );
    let status = if p.running {
        StatusCode::OK
    } else {
        StatusCode::from_u16(286).unwrap_or(StatusCode::OK)
    };
    Ok((status, Html(StackPartial { progress: p }.render()?)).into_response())
}

#[derive(Deserialize)]
pub struct StackForm {
    php: String,
    #[serde(default)]
    mariadb: Option<String>,
    #[serde(default)]
    postgresql: Option<String>,
    #[serde(default)]
    vsftpd: Option<String>,
    #[serde(default)]
    phpmyadmin: Option<String>,
    #[serde(default)]
    redis: Option<String>,
    #[serde(default)]
    ftp_port: Option<String>,
    #[serde(default)]
    _csrf: String,
}

/// The component list a submitted picker asks for.
pub(crate) fn stack_components(form: &StackForm) -> Vec<String> {
    let mut v = vec![form.php.trim().to_string()];
    for (on, name) in [
        (&form.mariadb, "mariadb"),
        (&form.postgresql, "postgresql"),
        (&form.redis, "redis"),
        (&form.vsftpd, "vsftpd"),
        (&form.phpmyadmin, "phpmyadmin"),
    ] {
        if on.is_some() {
            v.push(name.to_string());
        }
    }
    v
}

pub async fn post_stack(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<StackForm>,
) -> Result<Response, AppError> {
    let file = ensure_active(&state)?;
    let s = match wizard_admin(&ctx, "/setup/stack", false) {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    if !csrf_ok(&state, &s.sid, &form._csrf) {
        return Err(AppError::Forbidden);
    }
    let ftp_port: u16 = match form.ftp_port.as_deref().map(str::trim) {
        None | Some("") => 21,
        Some(p) => match p.parse::<u16>() {
            Ok(n) if n > 0 => n,
            _ => {
                return render_stack_error(
                    &state,
                    &ctx,
                    &file,
                    "The FTP port must be 1–65535.".into(),
                )
                .await
            }
        },
    };
    match rpc(
        &state,
        Request::SetupStackStart {
            components: stack_components(&form),
            ftp_port,
        },
    )
    .await?
    {
        RpcResponse::SetupStackStart { .. } => Ok(go(Step::Stack)),
        RpcResponse::Error(e) => render_stack_error(&state, &ctx, &file, e.to_string()).await,
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

async fn render_stack_error(
    state: &SharedState,
    ctx: &AuthCtx,
    file: &SetupFile,
    msg: String,
) -> Result<Response, AppError> {
    let csrf = super::session_csrf_token(state, ctx);
    let mut f = frame(file, Step::Stack, csrf.clone());
    f.error = Some(msg);
    let st = stack_status(state).await.unwrap_or_default();
    let tpl = StackTpl {
        f,
        picking: true,
        progress: stack_progress(st, csrf),
    };
    Ok((StatusCode::UNPROCESSABLE_ENTITY, Html(tpl.render()?)).into_response())
}

/// POST /setup/stack/done — move on once the install has finished (a failed
/// component can be added later on the Services page).
pub async fn post_stack_done(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<CsrfOnly>,
) -> Result<Response, AppError> {
    ensure_active(&state)?;
    let s = match wizard_admin(&ctx, "/setup/stack", false) {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    if !csrf_ok(&state, &s.sid, &form._csrf) {
        return Err(AppError::Forbidden);
    }
    let st = stack_status(&state).await?;
    if !matches!(st.state.as_str(), "succeeded" | "failed" | "interrupted") {
        return Ok(go(Step::Stack));
    }
    mark(&state, Step::Stack, false)?;
    Ok(go(Step::System))
}

// ───────────────────────── 5. Server identity ─────────────────────────

#[derive(Template)]
#[template(path = "setup_system.html")]
struct SystemTpl {
    f: Frame,
    hostname: String,
    current_hostname: String,
    timezone: String,
    timezones: Vec<String>,
    contact_email: String,
}

fn read_current_hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

fn read_current_timezone() -> String {
    std::fs::read_link("/etc/localtime")
        .ok()
        .and_then(|p| {
            p.to_string_lossy()
                .split_once("zoneinfo/")
                .map(|(_, z)| z.to_string())
        })
        .unwrap_or_else(|| "UTC".into())
}

async fn list_timezones() -> Vec<String> {
    match tokio::process::Command::new("timedatectl")
        .arg("list-timezones")
        .output()
        .await
    {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout)
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect(),
        _ => Vec::new(),
    }
}

async fn render_system(
    state: &SharedState,
    ctx: &AuthCtx,
    file: &SetupFile,
    s: &Session,
    values: Option<(String, String, String)>,
    error: Option<String>,
) -> Result<Response, AppError> {
    let current_hostname = read_current_hostname();
    let (hostname, timezone, contact_email) = match values {
        Some(v) => v,
        None => (
            current_hostname.clone(),
            read_current_timezone(),
            admin_user(state, s.user_id)
                .await
                .map(|u| u.email)
                .unwrap_or_default(),
        ),
    };
    let mut timezones = list_timezones().await;
    // No list (no timedatectl) → the template falls back to a text field.
    if !timezones.is_empty() && !timezone.is_empty() && !timezones.contains(&timezone) {
        timezones.insert(0, timezone.clone());
    }
    let mut f = frame(file, Step::System, super::session_csrf_token(state, ctx));
    let status = if error.is_some() {
        StatusCode::UNPROCESSABLE_ENTITY
    } else {
        StatusCode::OK
    };
    f.error = error;
    let tpl = SystemTpl {
        f,
        hostname,
        current_hostname,
        timezone,
        timezones,
        contact_email,
    };
    Ok((status, Html(tpl.render()?)).into_response())
}

pub async fn get_system(
    State(state): State<SharedState>,
    ctx: AuthCtx,
) -> Result<Response, AppError> {
    let file = ensure_active(&state)?;
    let s = match wizard_admin(&ctx, "/setup/system", false) {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    render_system(&state, &ctx, &file, &s, None, None).await
}

#[derive(Deserialize)]
pub struct SystemForm {
    hostname: String,
    timezone: String,
    contact_email: String,
    #[serde(default)]
    _csrf: String,
}

pub async fn post_system(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<SystemForm>,
) -> Result<Response, AppError> {
    let file = ensure_active(&state)?;
    let s = match wizard_admin(&ctx, "/setup/system", false) {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    if !csrf_ok(&state, &s.sid, &form._csrf) {
        return Err(AppError::Forbidden);
    }
    if form.contact_email.trim().is_empty() {
        let v = (form.hostname, form.timezone, form.contact_email);
        return render_system(
            &state,
            &ctx,
            &file,
            &s,
            Some(v),
            Some("Enter a contact email — Let's Encrypt needs one to issue certificates.".into()),
        )
        .await;
    }
    match rpc(
        &state,
        Request::SetupSystemApply {
            hostname: form.hostname.clone(),
            timezone: form.timezone.clone(),
            contact_email: form.contact_email.clone(),
        },
    )
    .await?
    {
        RpcResponse::SetupSystemApply { restarting } => {
            mark(&state, Step::System, false)?;
            Ok(Redirect::to(if restarting {
                "/setup/domain?restarted=1"
            } else {
                "/setup/domain"
            })
            .into_response())
        }
        RpcResponse::Error(e) => {
            let v = (form.hostname, form.timezone, form.contact_email);
            render_system(&state, &ctx, &file, &s, Some(v), Some(e.to_string())).await
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

// ───────────────────────── 6. Panel address ─────────────────────────

#[derive(Template)]
#[template(path = "setup_domain.html")]
struct DomainTpl {
    f: Frame,
    domain: String,
    addresses: Vec<String>,
    /// Waiting for the certificate (the progress block polls).
    waiting: bool,
    progress: DomainProgress,
    show_skip_dns: bool,
}

#[derive(Template)]
#[template(path = "_setup_domain_progress.html")]
struct DomainPartial {
    progress: DomainProgress,
}

pub struct DomainProgress {
    pub hostname: String,
    pub stage: String,
    pub message: String,
    pub done: bool,
    pub failed: bool,
    pub csrf: String,
}

/// This server's global addresses, for the "point an A record here" hint.
fn local_addresses() -> Vec<String> {
    let out = std::process::Command::new("hostname").arg("-I").output();
    match out {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout)
            .split_whitespace()
            .filter(|a| {
                a.parse::<std::net::IpAddr>()
                    .map(|ip| !ip.is_loopback() && !a.starts_with("fe80"))
                    .unwrap_or(false)
            })
            .map(str::to_string)
            .collect(),
        _ => Vec::new(),
    }
}

async fn panel_hostname(state: &SharedState) -> String {
    match rpc(state, Request::AgentConfigView).await {
        Ok(RpcResponse::AgentConfigView(c)) => c.cluster.panel_hostname,
        _ => state.panel_hostname.read().await.clone(),
    }
}

async fn domain_progress(state: &SharedState, csrf: String) -> DomainProgress {
    let snap = match rpc(state, Request::PanelCertStatus).await {
        Ok(RpcResponse::PanelCertStatus(v)) => v,
        _ => None,
    };
    match snap {
        Some(p) => DomainProgress {
            done: p.stage == "issued",
            failed: p.stage == "failed",
            hostname: p.hostname,
            stage: p.stage,
            message: p.message,
            csrf,
        },
        None => DomainProgress {
            hostname: String::new(),
            stage: "waiting".into(),
            message: String::new(),
            done: false,
            failed: false,
            csrf,
        },
    }
}

#[derive(Deserialize, Default)]
pub struct DomainQuery {
    #[serde(default)]
    wait: Option<String>,
    #[serde(default)]
    restarted: Option<String>,
}

pub async fn get_domain(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Query(q): Query<DomainQuery>,
) -> Result<Response, AppError> {
    let file = ensure_active(&state)?;
    if let Err(r) = wizard_admin(&ctx, "/setup/domain", false) {
        return Ok(r);
    }
    let mut f = frame(&file, Step::Domain, super::session_csrf_token(&state, &ctx));
    if q.restarted.is_some() {
        f.notice = Some(
            "Saved. The agent is restarting to pick up the new settings — that takes a few seconds."
                .into(),
        );
    }
    let csrf = f.csrf.clone();
    let tpl = DomainTpl {
        f,
        domain: panel_hostname(&state).await,
        addresses: local_addresses(),
        waiting: q.wait.is_some(),
        progress: domain_progress(&state, csrf).await,
        show_skip_dns: false,
    };
    Ok(Html(tpl.render()?).into_response())
}

pub async fn get_domain_status(
    State(state): State<SharedState>,
    ctx: AuthCtx,
) -> Result<Response, AppError> {
    ensure_active(&state)?;
    if let Err(r) = wizard_admin(&ctx, "/setup/domain", false) {
        return Ok(r);
    }
    let p = domain_progress(&state, super::session_csrf_token(&state, &ctx)).await;
    let status = if p.done || p.failed {
        StatusCode::from_u16(286).unwrap_or(StatusCode::OK)
    } else {
        StatusCode::OK
    };
    Ok((status, Html(DomainPartial { progress: p }.render()?)).into_response())
}

#[derive(Deserialize)]
pub struct DomainForm {
    domain: String,
    #[serde(default)]
    skip_dns_check: Option<String>,
    #[serde(default)]
    _csrf: String,
}

pub async fn post_domain(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<DomainForm>,
) -> Result<Response, AppError> {
    let file = ensure_active(&state)?;
    let s = match wizard_admin(&ctx, "/setup/domain", false) {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    if !csrf_ok(&state, &s.sid, &form._csrf) {
        return Err(AppError::Forbidden);
    }
    let domain = form
        .domain
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let resp = rpc(
        &state,
        Request::PanelProvision {
            hostname: domain.clone(),
            skip_dns_check: form.skip_dns_check.is_some(),
        },
    )
    .await;
    let (status, message) = match resp {
        Ok(RpcResponse::PanelProvision {
            status, message, ..
        }) => (status, message),
        Ok(RpcResponse::Error(e)) => ("error".to_string(), e.to_string()),
        Ok(_) => return Err(AppError::Internal("unexpected response".into())),
        // The agent restarts right after the identity step; a submit that
        // lands in that window is worth one honest sentence, not a 500.
        Err(_) => (
            "agent-unavailable".to_string(),
            "The agent is still restarting after the previous step. Wait a few seconds and \
             send this again."
                .to_string(),
        ),
    };
    if status == "ok" || status == "ok-cert-pending" {
        return Ok(Redirect::to("/setup/domain?wait=1").into_response());
    }
    let first_line = message
        .lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("The panel address could not be set up.")
        .to_string();
    let mut f = frame(&file, Step::Domain, super::session_csrf_token(&state, &ctx));
    f.error = Some(first_line);
    let csrf = f.csrf.clone();
    let tpl = DomainTpl {
        f,
        domain,
        addresses: local_addresses(),
        waiting: false,
        progress: domain_progress(&state, csrf).await,
        show_skip_dns: status == "dns-failed",
    };
    Ok((StatusCode::UNPROCESSABLE_ENTITY, Html(tpl.render()?)).into_response())
}

/// POST /setup/domain/continue — the certificate is live: hand the session
/// over to the new address. The cookie belongs to the IP origin and cannot
/// follow on its own, so a single-use, 60-second token carries it.
pub async fn post_domain_continue(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<CsrfOnly>,
) -> Result<Response, AppError> {
    ensure_active(&state)?;
    let s = match wizard_admin(&ctx, "/setup/domain", false) {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    if !csrf_ok(&state, &s.sid, &form._csrf) {
        return Err(AppError::Forbidden);
    }
    let host = panel_hostname(&state).await;
    let host_ok = redirect_host_ok(&host);
    mark(&state, Step::Domain, false)?;
    if !host_ok {
        return Ok(go(Step::Mail));
    }
    let token = state.setup.issue_handoff(Handoff {
        user_id: s.user_id,
        username: s.username.clone(),
        role: s.role.clone(),
        expires_at: hyperion_types::now_secs() + crate::setup::HANDOFF_TTL_SECS,
    });
    Ok(Redirect::to(&format!("https://{host}/setup/handoff?h={token}")).into_response())
}

/// A host name safe to put into a redirect (no scheme, port, path or
/// userinfo smuggled in).
fn redirect_host_ok(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= 253
        && h.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
}

#[derive(Deserialize)]
pub struct HandoffQuery {
    h: String,
}

/// GET /setup/handoff?h=… — on the new origin: trade the token for a
/// session cookie here and carry on with the wizard.
pub async fn get_handoff(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Query(q): Query<HandoffQuery>,
) -> Result<Response, AppError> {
    ensure_active(&state)?;
    let now = hyperion_types::now_secs();
    let Some(h) = state.setup.take_handoff(q.h.trim(), now) else {
        return Ok(Redirect::to("/login?next=%2Fsetup").into_response());
    };
    login::mint_session_redirect(
        &state,
        h.user_id,
        h.username,
        h.role,
        "/setup/mail",
        &headers,
        hyperion_auth::PURPOSE_SESSION,
        true,
    )
    .await
}

// ───────────────────────── 7. Outgoing mail ─────────────────────────

#[derive(Template)]
#[template(path = "setup_mail.html")]
struct MailTpl {
    f: Frame,
    host: String,
    port: String,
    security: String,
    user: String,
    password_set: bool,
    from_address: String,
    admin_email: String,
    saved: bool,
    test_result: Option<(bool, String)>,
}

async fn render_mail(
    state: &SharedState,
    ctx: &AuthCtx,
    file: &SetupFile,
    s: &Session,
    saved: bool,
    test_result: Option<(bool, String)>,
    error: Option<String>,
) -> Result<Response, AppError> {
    let cfg = match rpc(state, Request::AgentConfigView).await {
        Ok(RpcResponse::AgentConfigView(c)) => Some(c),
        _ => None,
    };
    let admin_email = admin_user(state, s.user_id)
        .await
        .map(|u| u.email)
        .unwrap_or_default();
    let (host, port, security, user, password_set, from_address) = match &cfg {
        Some(c) if c.email.smtp_host != "smtp.example.com" && !c.email.smtp_host.is_empty() => (
            c.email.smtp_host.clone(),
            c.email.smtp_port.to_string(),
            c.email.security.clone(),
            c.email.smtp_user.clone(),
            c.email.smtp_password_set,
            c.email.from_address.clone(),
        ),
        _ => {
            let domain = cfg
                .as_ref()
                .map(|c| c.cluster.panel_hostname.clone())
                .filter(|h| !h.is_empty())
                .unwrap_or_else(read_current_hostname);
            (
                String::new(),
                "587".into(),
                "starttls".into(),
                String::new(),
                false,
                // No name to put after the @ → leave it for the operator
                // rather than prefill a broken address.
                if domain.is_empty() {
                    String::new()
                } else {
                    format!("hyperion@{domain}")
                },
            )
        }
    };
    let mut f = frame(file, Step::Mail, super::session_csrf_token(state, ctx));
    let status = if error.is_some() {
        StatusCode::UNPROCESSABLE_ENTITY
    } else {
        StatusCode::OK
    };
    f.error = error;
    let tpl = MailTpl {
        f,
        host,
        port,
        security,
        user,
        password_set,
        from_address,
        admin_email,
        saved,
        test_result,
    };
    Ok((status, Html(tpl.render()?)).into_response())
}

#[derive(Deserialize, Default)]
pub struct SavedQuery {
    #[serde(default)]
    saved: Option<String>,
}

pub async fn get_mail(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Query(q): Query<SavedQuery>,
) -> Result<Response, AppError> {
    let file = ensure_active(&state)?;
    let s = match wizard_admin(&ctx, "/setup/mail", false) {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    render_mail(&state, &ctx, &file, &s, q.saved.is_some(), None, None).await
}

#[derive(Deserialize)]
pub struct MailForm {
    host: String,
    port: String,
    security: String,
    #[serde(default)]
    user: String,
    #[serde(default)]
    password: String,
    from_address: String,
    #[serde(default)]
    _csrf: String,
}

pub async fn post_mail(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<MailForm>,
) -> Result<Response, AppError> {
    let file = ensure_active(&state)?;
    let s = match wizard_admin(&ctx, "/setup/mail", false) {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    if !csrf_ok(&state, &s.sid, &form._csrf) {
        return Err(AppError::Forbidden);
    }
    if form.host.trim().is_empty() || form.from_address.trim().is_empty() {
        return render_mail(
            &state,
            &ctx,
            &file,
            &s,
            false,
            None,
            Some("Fill in the SMTP server and the From address.".into()),
        )
        .await;
    }
    let security = match form.security.as_str() {
        "tls" | "starttls" | "plain" => form.security.clone(),
        _ => "starttls".to_string(),
    };
    let admin_email = admin_user(&state, s.user_id)
        .await
        .map(|u| u.email)
        .unwrap_or_default();
    let mut fields = std::collections::BTreeMap::new();
    fields.insert("enabled".to_string(), "true".to_string());
    fields.insert("smtp_host".to_string(), form.host.trim().to_string());
    fields.insert("smtp_port".to_string(), form.port.trim().to_string());
    fields.insert("security".to_string(), security);
    fields.insert("smtp_user".to_string(), form.user.trim().to_string());
    if !form.password.is_empty() {
        fields.insert("smtp_password".to_string(), form.password.clone());
    }
    fields.insert(
        "from_address".to_string(),
        form.from_address.trim().to_string(),
    );
    fields.insert("from_name".to_string(), "Hyperion".to_string());
    if !admin_email.is_empty() {
        fields.insert("default_to".to_string(), admin_email);
    }
    match rpc(
        &state,
        Request::EmailConfigSet {
            fields: fields.into(),
        },
    )
    .await?
    {
        RpcResponse::EmailConfigSet => Ok(Redirect::to("/setup/mail?saved=1").into_response()),
        RpcResponse::Error(e) => {
            render_mail(&state, &ctx, &file, &s, false, None, Some(e.to_string())).await
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

/// POST /setup/mail/test — send a real message to the administrator.
pub async fn post_mail_test(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<CsrfOnly>,
) -> Result<Response, AppError> {
    let file = ensure_active(&state)?;
    let s = match wizard_admin(&ctx, "/setup/mail", false) {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    if !csrf_ok(&state, &s.sid, &form._csrf) {
        return Err(AppError::Forbidden);
    }
    let to = admin_user(&state, s.user_id)
        .await
        .map(|u| u.email)
        .unwrap_or_default();
    let result = match rpc(&state, Request::EmailSendTest { to }).await {
        Ok(RpcResponse::EmailSendTest { smtp_code }) => (true, smtp_code),
        Ok(RpcResponse::Error(e)) => (false, e.to_string()),
        Ok(_) => (false, "unexpected response from the agent".into()),
        Err(_) => (
            false,
            "The agent is restarting to apply the mail settings. Try again in a few seconds."
                .into(),
        ),
    };
    if result.0 {
        mark(&state, Step::Mail, false)?;
    }
    let file = state.setup.read().unwrap_or(file);
    render_mail(&state, &ctx, &file, &s, true, Some(result), None).await
}

/// POST /setup/mail/done — mail is set up; carry on.
pub async fn post_mail_done(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<CsrfOnly>,
) -> Result<Response, AppError> {
    ensure_active(&state)?;
    let s = match wizard_admin(&ctx, "/setup/mail", false) {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    if !csrf_ok(&state, &s.sid, &form._csrf) {
        return Err(AppError::Forbidden);
    }
    mark(&state, Step::Mail, false)?;
    Ok(go(Step::Backups))
}

// ───────────────────────── 8. Backups ─────────────────────────

#[derive(Template)]
#[template(path = "setup_backups.html")]
struct BackupsTpl {
    f: Frame,
    targets: Vec<hyperion_types::BackupTargetView>,
    endpoint: String,
    bucket: String,
    region: String,
    access_key: String,
    probe: Option<(bool, String)>,
}

async fn backup_targets(state: &SharedState) -> Vec<hyperion_types::BackupTargetView> {
    match rpc(state, Request::BackupTargetList).await {
        Ok(RpcResponse::BackupTargetList(v)) => v,
        _ => Vec::new(),
    }
}

pub async fn get_backups(
    State(state): State<SharedState>,
    ctx: AuthCtx,
) -> Result<Response, AppError> {
    let file = ensure_active(&state)?;
    if let Err(r) = wizard_admin(&ctx, "/setup/backups", false) {
        return Ok(r);
    }
    let tpl = BackupsTpl {
        f: frame(
            &file,
            Step::Backups,
            super::session_csrf_token(&state, &ctx),
        ),
        targets: backup_targets(&state).await,
        endpoint: String::new(),
        bucket: String::new(),
        region: "auto".into(),
        access_key: String::new(),
        probe: None,
    };
    Ok(Html(tpl.render()?).into_response())
}

#[derive(Deserialize)]
pub struct BackupsForm {
    endpoint: String,
    bucket: String,
    #[serde(default)]
    region: String,
    access_key: String,
    secret_key: String,
    #[serde(default)]
    _csrf: String,
}

pub async fn post_backups(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<BackupsForm>,
) -> Result<Response, AppError> {
    let file = ensure_active(&state)?;
    let s = match wizard_admin(&ctx, "/setup/backups", false) {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    if !csrf_ok(&state, &s.sid, &form._csrf) {
        return Err(AppError::Forbidden);
    }
    let region = if form.region.trim().is_empty() {
        "auto".to_string()
    } else {
        form.region.trim().to_string()
    };
    let saved = rpc(
        &state,
        Request::BackupTargetUpsert {
            id: None,
            name: "Off-site copy".into(),
            kind: "s3".into(),
            endpoint: form.endpoint.trim().to_string(),
            bucket: form.bucket.trim().to_string(),
            region: region.clone(),
            access_key_id: form.access_key.trim().to_string(),
            secret_key: Some(form.secret_key.clone()).filter(|s| !s.is_empty()),
            age_recipient: None,
            retention_daily: 7,
            retention_weekly: 0,
            retention_monthly: 0,
            enabled: true,
        },
    )
    .await?;
    let (probe, error) = match saved {
        RpcResponse::BackupTargetUpserted { id } => {
            match rpc(&state, Request::BackupTargetProbe { id }).await {
                Ok(RpcResponse::BackupTargetProbe(p)) => (Some((p.ok, p.message)), None),
                Ok(RpcResponse::Error(e)) => (Some((false, e.to_string())), None),
                _ => (
                    Some((false, "the agent did not answer the check".into())),
                    None,
                ),
            }
        }
        RpcResponse::Error(e) => (None, Some(e.to_string())),
        _ => return Err(AppError::Internal("unexpected response".into())),
    };
    if probe.as_ref().map(|p| p.0).unwrap_or(false) {
        mark(&state, Step::Backups, false)?;
    }
    let file = state.setup.read().unwrap_or(file);
    let mut f = frame(
        &file,
        Step::Backups,
        super::session_csrf_token(&state, &ctx),
    );
    f.error = error;
    let tpl = BackupsTpl {
        f,
        targets: backup_targets(&state).await,
        endpoint: form.endpoint,
        bucket: form.bucket,
        region,
        access_key: form.access_key,
        probe,
    };
    Ok(Html(tpl.render()?).into_response())
}

/// POST /setup/backups/done
pub async fn post_backups_done(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<CsrfOnly>,
) -> Result<Response, AppError> {
    ensure_active(&state)?;
    let s = match wizard_admin(&ctx, "/setup/backups", false) {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    if !csrf_ok(&state, &s.sid, &form._csrf) {
        return Err(AppError::Forbidden);
    }
    mark(&state, Step::Backups, false)?;
    Ok(go(Step::Review))
}

// ───────────────────────── 9. Review ─────────────────────────

pub struct Check {
    pub label: &'static str,
    /// "ok" | "warn" | "err" | "info"
    pub tone: &'static str,
    pub pill: &'static str,
    pub detail: String,
    /// Where to fix it.
    pub href: Option<&'static str>,
}

#[derive(Template)]
#[template(path = "setup_review.html")]
struct ReviewTpl {
    f: Frame,
    checks: Vec<Check>,
    blocking: bool,
    warnings: usize,
}

async fn review_checks(state: &SharedState, s: &Session, file: &SetupFile) -> Vec<Check> {
    let mut out = Vec::new();

    let user = admin_user(state, s.user_id).await;
    out.push(match user {
        Some(u) if u.totp_enrolled => Check {
            label: "Administrator",
            tone: "ok",
            pill: "ok",
            detail: format!("{} · two-factor on", u.username),
            href: None,
        },
        Some(u) => Check {
            label: "Administrator",
            tone: "warn",
            pill: "no 2FA",
            detail: format!("{} · two-factor sign-in is off", u.username),
            href: Some("/profile"),
        },
        None => Check {
            label: "Administrator",
            tone: "err",
            pill: "missing",
            detail: "the account could not be read".into(),
            href: None,
        },
    });

    let st = stack_status(state).await.unwrap_or_default();
    let installed: Vec<String> = st
        .components
        .iter()
        .filter(|c| c.state == "done")
        .map(|c| component_label(&c.name))
        .collect();
    let failed: Vec<String> = st
        .components
        .iter()
        .filter(|c| c.state == "failed")
        .map(|c| component_label(&c.name))
        .collect();
    out.push(if st.state == "idle" || installed.is_empty() {
        Check {
            label: "Server software",
            tone: "err",
            pill: "not installed",
            detail: "no PHP yet — sites cannot run".into(),
            href: Some("/setup/stack"),
        }
    } else if !failed.is_empty() {
        Check {
            label: "Server software",
            tone: "warn",
            pill: "partly",
            detail: format!("{} · failed: {}", installed.join(", "), failed.join(", ")),
            href: Some("/services"),
        }
    } else {
        Check {
            label: "Server software",
            tone: "ok",
            pill: "ok",
            detail: installed.join(", "),
            href: None,
        }
    });

    out.push(Check {
        label: "Server identity",
        tone: "ok",
        pill: "ok",
        detail: [read_current_hostname(), read_current_timezone()]
            .into_iter()
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join(" · "),
        href: None,
    });

    let cfg = match rpc(state, Request::AgentConfigView).await {
        Ok(RpcResponse::AgentConfigView(c)) => Some(c),
        _ => None,
    };
    let panel = cfg
        .as_ref()
        .map(|c| c.cluster.panel_hostname.clone())
        .unwrap_or_default();
    let cert = match rpc(state, Request::PanelCertStatus).await {
        Ok(RpcResponse::PanelCertStatus(v)) => v,
        _ => None,
    };
    out.push(if panel.is_empty() {
        Check {
            label: "Panel address",
            tone: "warn",
            pill: "skipped",
            detail: "the panel stays on its IP address with a self-signed certificate".into(),
            href: Some("/settings#panel-domain"),
        }
    } else {
        match cert.as_ref().map(|c| c.stage.as_str()) {
            Some("failed") => Check {
                label: "Panel address",
                tone: "err",
                pill: "no certificate",
                detail: format!("https://{panel} · Let's Encrypt refused the certificate"),
                href: Some("/settings#panel-domain"),
            },
            Some("issued") | None => Check {
                label: "Panel address",
                tone: "ok",
                pill: "ok",
                detail: format!("https://{panel}"),
                href: None,
            },
            Some(_) => Check {
                label: "Panel address",
                tone: "info",
                pill: "issuing",
                detail: format!("https://{panel} · certificate on its way"),
                href: None,
            },
        }
    });

    let email = cfg.as_ref().map(|c| c.email.clone()).unwrap_or_default();
    out.push(if email.enabled && !email.smtp_host.is_empty() {
        Check {
            label: "Outgoing mail",
            tone: if file.is_done(Step::Mail) && !file.is_skipped(Step::Mail) {
                "ok"
            } else {
                "info"
            },
            pill: if file.is_done(Step::Mail) && !file.is_skipped(Step::Mail) {
                "ok"
            } else {
                "not tested"
            },
            detail: format!("via {}", email.smtp_host),
            href: None,
        }
    } else {
        Check {
            label: "Outgoing mail",
            tone: "warn",
            pill: "skipped",
            detail: "no alerts or password-reset emails until a mail server is set".into(),
            href: Some("/settings#mail"),
        }
    });

    let targets = backup_targets(state).await;
    out.push(if targets.iter().any(|t| t.enabled) {
        Check {
            label: "Off-site backups",
            tone: "ok",
            pill: "ok",
            detail: targets
                .iter()
                .filter(|t| t.enabled)
                .map(|t| format!("{} ({})", t.bucket, t.endpoint))
                .collect::<Vec<_>>()
                .join(", "),
            href: None,
        }
    } else {
        Check {
            label: "Off-site backups",
            tone: "warn",
            pill: "skipped",
            detail: "only copies on this server".into(),
            href: Some("/settings/backups"),
        }
    });

    out
}

pub async fn get_review(
    State(state): State<SharedState>,
    ctx: AuthCtx,
) -> Result<Response, AppError> {
    let file = ensure_active(&state)?;
    let s = match wizard_admin(&ctx, "/setup/review", false) {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let checks = review_checks(&state, &s, &file).await;
    let blocking = checks.iter().any(|c| c.tone == "err");
    let warnings = checks.iter().filter(|c| c.tone == "warn").count();
    let tpl = ReviewTpl {
        f: frame(&file, Step::Review, super::session_csrf_token(&state, &ctx)),
        checks,
        blocking,
        warnings,
    };
    Ok(Html(tpl.render()?).into_response())
}

/// POST /setup/finish — leave setup mode for good.
pub async fn post_finish(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<CsrfOnly>,
) -> Result<Response, AppError> {
    let file = ensure_active(&state)?;
    let s = match wizard_admin(&ctx, "/setup/review", false) {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    if !csrf_ok(&state, &s.sid, &form._csrf) {
        return Err(AppError::Forbidden);
    }
    // PHP is the one thing a hosting server cannot do without.
    let st = stack_status(&state).await.unwrap_or_default();
    if !st
        .components
        .iter()
        .any(|c| c.name.starts_with("php") && c.state == "done")
    {
        let checks = review_checks(&state, &s, &file).await;
        let warnings = checks.iter().filter(|c| c.tone == "warn").count();
        let mut f = frame(&file, Step::Review, super::session_csrf_token(&state, &ctx));
        f.error = Some("Install PHP first — sites cannot run without it.".into());
        let tpl = ReviewTpl {
            f,
            checks,
            blocking: true,
            warnings,
        };
        return Ok((StatusCode::UNPROCESSABLE_ENTITY, Html(tpl.render()?)).into_response());
    }
    state
        .setup
        .update(|f| {
            f.mark_done(Step::Review);
            f.state = crate::setup::STATE_COMPLETED.into();
            f.completed_at = hyperion_types::now_secs();
            f.code_sha256.clear();
        })
        .map_err(|e| AppError::Internal(format!("save setup state: {e}")))?;
    tracing::info!(user = %s.username, "setup finished");
    Ok(Redirect::to("/").into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_form_rules() {
        let pw = "correct-horse-battery";
        assert!(admin_form_problem("kevin", "k@example.cz", pw, pw).is_none());
        assert!(admin_form_problem("", "k@example.cz", pw, pw).is_some());
        assert!(admin_form_problem("ke vin", "k@example.cz", pw, pw).is_some());
        assert!(admin_form_problem("kevin", "not-an-email", pw, pw).is_some());
        assert!(admin_form_problem("kevin", "k@localhost", pw, pw).is_some());
        assert!(admin_form_problem("kevin", "k@example.cz", "short", "short").is_some());
        assert!(admin_form_problem("kevin", "k@example.cz", pw, "other-password-1").is_some());
    }

    #[test]
    fn picker_maps_to_components() {
        let f = StackForm {
            php: "php8.3".into(),
            mariadb: Some("on".into()),
            postgresql: None,
            vsftpd: Some("on".into()),
            phpmyadmin: Some("on".into()),
            redis: None,
            ftp_port: None,
            _csrf: String::new(),
        };
        assert_eq!(
            stack_components(&f),
            vec!["php8.3", "mariadb", "vsftpd", "phpmyadmin"]
        );
    }

    #[test]
    fn handoff_host_must_be_a_bare_name() {
        assert!(redirect_host_ok("panel.example.net"));
        assert!(!redirect_host_ok(""));
        assert!(!redirect_host_ok("evil.example/x"));
        assert!(!redirect_host_ok("a@b.example"));
        assert!(!redirect_host_ok("panel.example.net:8443"));
    }

    #[test]
    fn codes_are_shown_grouped() {
        assert_eq!(pretty_code("k7qm4xwd9hprt2nv"), "K7QM-4XWD-9HPR-T2NV");
        assert_eq!(pretty_code("K7QM-4XWD-9HPR-T2NV"), "K7QM-4XWD-9HPR-T2NV");
    }
}
