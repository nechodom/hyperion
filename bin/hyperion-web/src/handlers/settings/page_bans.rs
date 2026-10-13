//! `GET /settings/bans` — when repeated failures earn an address a firewall
//! ban, and the country database behind per-site country blocking.
//!
//! The scanner's numbers are the master's `[fail2ban]` section, read
//! straight from `/etc/hyperion/agent.toml` (they are not part of
//! `AgentConfigView`); the settings sync copies the section to every node.
//! GeoIP lives on the master: the credentials in `/etc/GeoIP.conf` and the
//! derived tables under `/var/lib/hyperion/geoip`.

use super::chrome::{self, Chrome, PageQuery};
use super::Fail2banView;
use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::state::SharedState;
use askama::Template;
use axum::extract::{Query, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use hyperion_state::capabilities::Capability;

#[allow(unused_imports)] // askama resolves {{ x|datetime }} through this
use crate::filters;

/// The master's agent.toml — the file the settings sync copies `[fail2ban]`
/// from.
const AGENT_TOML: &str = "/etc/hyperion/agent.toml";

/// The scanner card's form values, with each duration also in the units an
/// operator thinks in. The fields stay in seconds (that is what the agent
/// validates and stores); the human reading sits next to each one.
pub struct ScannerCard {
    pub view: Fail2banView,
    pub window_h: String,
    pub ban_h: String,
    pub repeat_h: String,
    pub lookback_h: String,
}

impl ScannerCard {
    fn new(view: Fail2banView) -> Self {
        let c = &view.cfg;
        Self {
            window_h: human_secs(c.window_secs),
            ban_h: human_secs(c.ban_ttl_secs),
            repeat_h: human_secs(c.repeat_ttl_secs),
            lookback_h: if c.repeat_lookback_secs == 0 {
                LOOKBACK_ZERO.to_string()
            } else {
                human_secs(c.repeat_lookback_secs)
            },
            view,
        }
    }
}

/// What a look-back of 0 means; the template's script shows the same words.
const LOOKBACK_ZERO: &str = "never escalates";

/// A duration in seconds as the operator reads it: `= 10 min`, `= 1 h 30 min`,
/// `= 7 d`. At most two units, largest first; when that drops a remainder the
/// sign is `≈` instead of `=`. Negative input (a hand-edited file) gives an
/// empty string rather than a reading of nonsense.
///
/// The template's inline script recomputes this while the operator types and
/// must produce the same text — change both together.
pub(crate) fn human_secs(n: i64) -> String {
    const UNITS: [(&str, i64); 4] = [("d", 86_400), ("h", 3_600), ("min", 60), ("s", 1)];
    if n < 0 {
        return String::new();
    }
    if n == 0 {
        return "= 0 s".into();
    }
    // n ≥ 1, so the last unit always matches.
    let i = UNITS
        .iter()
        .position(|(_, u)| n >= *u)
        .unwrap_or(UNITS.len() - 1);
    let (big, big_u) = UNITS[i];
    let a = n / big_u;
    let mut rest = n - a * big_u;
    let mut out = format!("{a} {big}");
    if let Some((small, small_u)) = UNITS.get(i + 1) {
        let b = rest / small_u;
        if b > 0 {
            out.push_str(&format!(" {b} {small}"));
            rest -= b * small_u;
        }
    }
    format!("{} {out}", if rest == 0 { "=" } else { "≈" })
}

#[derive(Template)]
#[template(path = "settings_bans.html")]
struct PageTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    chrome: Chrome,
    csrf_token: String,
    /// `None` when agent.toml could not be read or parsed; `scanner_error`
    /// then says which.
    scanner: Option<ScannerCard>,
    scanner_error: String,
    geoip_installed: bool,
    geoip_updated_at: i64,
    /// Credentials were found (`/etc/GeoIP.conf`), so a refresh can run.
    geoip_configured: bool,
    /// The account id on file — never the licence key.
    geoip_account_id: String,
}

pub async fn get_bans(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Query(q): Query<PageQuery>,
) -> Result<Response, AppError> {
    if !ctx.can(Capability::SettingsManage) {
        return Ok(Redirect::to("/").into_response());
    }
    let (chrome, _nodes) = chrome::chrome(&state, &ctx, "bans", &q).await;
    let (toml_res, geoip_res, geoip_account) = tokio::join!(
        tokio::fs::read_to_string(AGENT_TOML),
        hyperion_rpc_client::call(&state.agent_socket, Request::GeoipStatus),
        super::hyperion_adapters_geoip_creds(&state),
    );
    let (scanner, scanner_error) = match toml_res {
        Ok(raw) => match super::parse_fail2ban_section(&raw) {
            Some(v) => (Some(ScannerCard::new(v)), String::new()),
            None => (None, "it is not valid TOML".to_string()),
        },
        Err(e) => (None, format!("it could not be read: {e}")),
    };
    let (geoip_installed, geoip_updated_at) = match geoip_res {
        Ok(RpcResponse::GeoipStatus {
            installed,
            updated_at,
        }) => (installed, updated_at),
        _ => (false, 0),
    };
    let tpl = PageTpl {
        username: &ctx.username,
        user_initial: crate::handlers::user_initial(&ctx.username),
        active: "settings",
        css_version: crate::handlers::css_version(),
        htmx_version: crate::handlers::htmx_version(),
        chrome,
        csrf_token: crate::handlers::session_csrf_token(&state, &ctx),
        scanner,
        scanner_error,
        geoip_installed,
        geoip_updated_at,
        geoip_configured: geoip_account.is_some(),
        geoip_account_id: geoip_account.unwrap_or_default(),
    };
    Ok(Html(tpl.render()?).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page(scanner: Option<ScannerCard>, can_edit: bool) -> String {
        PageTpl {
            username: "kevin",
            user_initial: 'K',
            active: "settings",
            css_version: "x",
            htmx_version: "x",
            chrome: Chrome {
                section: "bans",
                title: "Brute-force & GeoIP",
                lead: "",
                can_edit,
                has_nodes: true,
                flash: None,
                flash_error: None,
            },
            csrf_token: "tok".into(),
            scanner,
            scanner_error: "it could not be read: nope".into(),
            geoip_installed: false,
            geoip_updated_at: 0,
            geoip_configured: true,
            geoip_account_id: "123456".into(),
        }
        .render()
        .expect("render")
    }

    #[test]
    fn the_scanner_form_posts_every_field_in_seconds_with_a_reading_beside_it() {
        let view = super::super::parse_fail2ban_section("[fail2ban]\nrepeat_lookback_secs = 0\n")
            .expect("valid toml");
        let html = page(Some(ScannerCard::new(view)), true);
        for name in [
            "window_secs",
            "http_threshold",
            "ssh_threshold",
            "ftp_threshold",
            "mail_threshold",
            "waf_threshold",
            "ban_ttl_secs",
            "repeat_ttl_secs",
            "repeat_lookback_secs",
        ] {
            assert!(html.contains(&format!("name=\"{name}\"")), "{name} missing");
        }
        assert!(html.contains(r#"name="_checkboxes" value="enabled""#));
        assert!(html.contains(r#"name="_return_tab" value="bruteforce-scanner""#));
        assert!(html.contains(r#"id="f2b_ttl_human">= 1 h<"#));
        assert!(html.contains(r#"id="f2b_lookback_human">never escalates<"#));
        // fail2ban is synced now; the per-host warning must not come back.
        assert!(!html.contains("This form edits"));
        assert!(html.contains("All nodes"));
    }

    #[test]
    fn an_unreadable_file_shows_why_and_no_form() {
        let html = page(None, true);
        assert!(html.contains(r#"id="bruteforce-scanner""#));
        assert!(html.contains("it could not be read: nope"));
        assert!(!html.contains(r#"value="fail2ban""#));
    }

    #[test]
    fn the_licence_key_is_never_rendered_and_forms_lock_for_non_owners() {
        let html = page(None, false);
        assert!(html.contains(r#"value="123456""#));
        assert!(html.contains("stored — type a new one to replace it"));
        assert!(html.contains(r#"<fieldset class="group" disabled>"#));
        assert!(html.contains(r#"form="geoip-refresh""#));
    }

    #[test]
    fn whole_units_read_exactly() {
        assert_eq!(human_secs(45), "= 45 s");
        assert_eq!(human_secs(60), "= 1 min");
        assert_eq!(human_secs(600), "= 10 min");
        assert_eq!(human_secs(3_600), "= 1 h");
        assert_eq!(human_secs(86_400), "= 1 d");
        assert_eq!(human_secs(7 * 86_400), "= 7 d");
        assert_eq!(human_secs(31_536_000), "= 365 d");
    }

    #[test]
    fn two_units_are_shown_and_a_dropped_rest_is_approximate() {
        assert_eq!(human_secs(5_400), "= 1 h 30 min");
        assert_eq!(human_secs(90), "= 1 min 30 s");
        assert_eq!(human_secs(3_661), "≈ 1 h 1 min");
        // The second unit is the NEXT one down, never a smaller one: 1 d
        // and 1 min is not "1 d 1 min".
        assert_eq!(human_secs(86_460), "≈ 1 d");
    }

    #[test]
    fn zero_and_nonsense() {
        assert_eq!(human_secs(0), "= 0 s");
        assert_eq!(human_secs(-5), "");
    }

    #[test]
    fn the_agent_defaults_read_as_round_numbers() {
        let c = hyperion_core::Fail2banConfig::default();
        assert_eq!(human_secs(c.window_secs), "= 10 min");
        assert_eq!(human_secs(c.ban_ttl_secs), "= 1 h");
        assert_eq!(human_secs(c.repeat_ttl_secs), "= 1 d");
    }
}
