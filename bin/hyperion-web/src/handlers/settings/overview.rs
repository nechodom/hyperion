//! `GET /settings` — the Settings overview.
//!
//! One row per Settings page saying, in a sentence, what that page is set to
//! right now, and above them the few things worth acting on. It answers "is
//! this install set up, and what is missing?" without opening nine pages —
//! and it is where a pre-upgrade `/settings#<card>` bookmark is sent on to
//! the card's new page.

use super::chrome::{self, card_url, Chrome, PageQuery};
use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::state::SharedState;
use askama::Template;
use axum::extract::{Query, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use hyperion_state::capabilities::Capability;
use hyperion_types::AgentConfigView;

#[derive(Template)]
#[template(path = "settings_overview.html")]
struct OverviewTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    chrome: Chrome,
    verdict: Verdict,
    attention: Vec<Attention>,
    groups: Vec<RowGroup>,
    /// `{"<old id>": "<new url>", …}` for the bookmark redirect script.
    legacy_json: String,
}

/// The line above everything: is anything wrong?
pub struct Verdict {
    /// `ok` / `warn` / `err` — the `.svc-verdict` tone.
    pub tone: &'static str,
    pub text: String,
}

/// One thing worth acting on, linked to the card that fixes it.
pub struct Attention {
    /// `warn` / `err` count toward the verdict; `info` is listed but does not.
    pub tone: &'static str,
    pub text: String,
    pub href: String,
}

/// A sub-navigation heading and its pages, as overview rows.
pub struct RowGroup {
    pub label: &'static str,
    pub rows: Vec<Row>,
}

pub struct Row {
    pub slug: &'static str,
    pub title: &'static str,
    /// What the page is set to, in one sentence.
    pub state: String,
}

/// Everything the overview reads, gathered first so the sentences and the
/// attention list are a pure function of it (and testable).
#[derive(Default)]
pub struct Facts {
    pub config: AgentConfigView,
    /// The master's config could not be read — every sentence below is then
    /// built from defaults and must not be believed.
    pub config_error: Option<String>,
    pub update_available: bool,
    /// S3 targets that really take a copy (switched on, an S3 kind, secret
    /// key on file) — judged by the Backups page's own row logic, so the
    /// overview and that page cannot disagree.
    pub s3_active: usize,
    /// The FTP/SFTP target takes a copy (on AND has a host).
    pub ftp_active: bool,
    /// `[fail2ban] enabled`; `None` when agent.toml did not parse.
    pub fail2ban_on: Option<bool>,
    pub geoip_installed: bool,
    pub letter_lang: String,
    pub letters_rewritten: usize,
    /// Enrolled worker nodes.
    pub nodes: usize,
    /// Workers whose last settings sync did not leave them with the master's
    /// settings (failed, or an agent too old to take them), by label.
    pub sync_behind: Vec<String>,
    /// Workers the sync has reported on at all.
    pub sync_known: usize,
    /// Workers that have published a response-signing key.
    pub resp_auth_ready: usize,
}

pub async fn get_overview(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Query(q): Query<PageQuery>,
) -> Result<Response, AppError> {
    if !ctx.can(Capability::SettingsManage) {
        return Ok(Redirect::to("/").into_response());
    }
    // `/settings?mail_node=X#mail` was the old per-node Mail link; the
    // fragment never reaches the server, but the node does.
    if !q.mail_node.trim().is_empty() {
        let node: String =
            url::form_urlencoded::byte_serialize(q.mail_node.trim().as_bytes()).collect();
        return Ok(Redirect::to(&format!("/settings/mail?node={node}")).into_response());
    }
    let (chrome, nodes) = chrome::chrome(&state, &ctx, "overview", &q).await;
    let facts = gather(&state, &nodes).await;
    let (verdict, attention) = assess(&facts, chrome.has_nodes);
    let groups = rows(&facts, &chrome);
    let legacy: std::collections::BTreeMap<String, String> =
        chrome::legacy_targets().into_iter().collect();
    // Emitted with `|safe` into a <script>; the values are our own paths,
    // but keep the one sequence that could end the element out regardless.
    let legacy_json = serde_json::to_string(&legacy)
        .unwrap_or_else(|_| "{}".into())
        .replace("</", "<\\/");
    let tpl = OverviewTpl {
        username: &ctx.username,
        user_initial: crate::handlers::user_initial(&ctx.username),
        active: "settings",
        css_version: crate::handlers::css_version(),
        htmx_version: crate::handlers::htmx_version(),
        chrome,
        verdict,
        attention,
        groups,
        legacy_json,
    };
    Ok(Html(tpl.render()?).into_response())
}

async fn gather(state: &SharedState, nodes: &[hyperion_types::NodeSummary]) -> Facts {
    let short = std::time::Duration::from_secs(4);
    let (config_res, update_res, targets_res, geoip_res, toml_res) = tokio::join!(
        hyperion_rpc_client::call(&state.agent_socket, Request::AgentConfigView),
        // A release check can reach the network; a slow one must not hold
        // the overview, so it simply reads as "no update known".
        tokio::time::timeout(
            short,
            hyperion_rpc_client::call(
                &state.agent_socket,
                Request::UpdateCheck {
                    force_refresh: false
                },
            )
        ),
        hyperion_rpc_client::call(&state.agent_socket, Request::BackupTargetList),
        hyperion_rpc_client::call(&state.agent_socket, Request::GeoipStatus),
        tokio::fs::read_to_string("/etc/hyperion/agent.toml"),
    );
    let mut f = Facts::default();
    match config_res {
        Ok(RpcResponse::AgentConfigView(c)) => f.config = c,
        Ok(RpcResponse::Error(e)) => f.config_error = Some(e.to_string()),
        Ok(_) => f.config_error = Some("unexpected agent response".into()),
        Err(e) => f.config_error = Some(format!("rpc: {e}")),
    }
    f.ftp_active = super::page_backups::ftp_row(&f.config.backup_remote).active;
    if let Ok(Ok(RpcResponse::UpdateCheck(u))) = update_res {
        f.update_available = u.update_available;
    }
    if let Ok(RpcResponse::BackupTargetList(targets)) = targets_res {
        for t in targets {
            let on_disk = match t.secret_key_id.as_deref() {
                Some(p) => tokio::fs::metadata(p).await.is_ok(),
                None => false,
            };
            if super::page_backups::s3_row(t, on_disk).active {
                f.s3_active += 1;
            }
        }
    }
    if let Ok(RpcResponse::GeoipStatus { installed, .. }) = geoip_res {
        f.geoip_installed = installed;
    }
    if let Ok(raw) = toml_res {
        f.fail2ban_on = super::parse_fail2ban_section(&raw).map(|v| v.cfg.enabled);
        let cat = hyperion_core::service::letter_catalog_from_toml(&raw);
        f.letter_lang = cat.lang.as_str().to_string();
        f.letters_rewritten = cat.overrides.values().filter(|v| !v.is_empty()).count();
    }
    f.nodes = nodes.len();
    let sync = state.cluster_sync.all().await;
    for n in nodes {
        if let Some(s) = sync.get(&n.node_id) {
            f.sync_known += 1;
            if !s.is_ok() {
                f.sync_behind.push(node_label(n));
            }
        }
    }
    f.resp_auth_ready = nodes
        .iter()
        .filter(|n| !n.resp_pubkey.as_deref().unwrap_or("").trim().is_empty())
        .count();
    f
}

fn node_label(n: &hyperion_types::NodeSummary) -> String {
    if n.label.trim().is_empty() {
        n.node_id.clone()
    } else {
        n.label.clone()
    }
}

/// How many admin addresses a `default_to` list holds — split the way the
/// mailer splits it (commas, semicolons, whitespace; only things with an @).
pub fn address_count(list: &str) -> usize {
    list.split(|c: char| c == ',' || c == ';' || c.is_whitespace())
        .filter(|a| a.contains('@'))
        .count()
}

fn plural(n: usize, one: &str, many: &str) -> String {
    if n == 1 {
        format!("{n} {one}")
    } else {
        format!("{n} {many}")
    }
}

/// The verdict and the list of things worth acting on.
pub fn assess(f: &Facts, has_nodes: bool) -> (Verdict, Vec<Attention>) {
    let c = &f.config;
    let mut out: Vec<Attention> = Vec::new();
    if let Some(e) = &f.config_error {
        out.push(Attention {
            tone: "err",
            text: format!(
                "The agent's settings could not be read ({e}). What this page says is built from defaults."
            ),
            href: "/services".into(),
        });
    }
    if c.cluster.panel_hostname.trim().is_empty() {
        out.push(Attention {
            tone: "warn",
            text: "The panel has no domain yet — it is reached by IP, with a certificate browsers do not trust.".into(),
            href: card_url("panel-domain", ""),
        });
    }
    if c.cluster.protection_mode == "snapshots" {
        out.push(Attention {
            tone: "warn",
            text: "Only snapshots are kept, and snapshots never leave the node — losing a node loses its sites.".into(),
            href: card_url("protection-mode", ""),
        });
    } else if !f.ftp_active && f.s3_active == 0 {
        out.push(Attention {
            tone: "warn",
            text: "Backups are not copied off-site — losing a server loses its sites and their backups.".into(),
            href: card_url("offsite-targets", ""),
        });
    }
    // Admin mail only leaves through the relay: with `[email]` off the
    // addresses are kept but nothing is sent to them.
    let addresses = address_count(&c.email.default_to);
    if !c.slack.default_webhook_set && !(c.email.enabled && addresses > 0) {
        out.push(if addresses > 0 {
            Attention {
                tone: "warn",
                text: "Alerts reach nobody — the administrator addresses get no mail while the \
                       outgoing relay is off, and Slack is not connected."
                    .into(),
                href: card_url("smtp-relay", ""),
            }
        } else {
            Attention {
                tone: "warn",
                text: "Alerts reach nobody — connect Slack or add an administrator address.".into(),
                href: card_url("alert-recipients", ""),
            }
        });
    }
    if f.fail2ban_on == Some(false) {
        out.push(Attention {
            tone: "warn",
            text: "The brute-force scanner is off — repeated failed logins are never banned."
                .into(),
            href: card_url("bruteforce-scanner", ""),
        });
    }
    if has_nodes && !f.sync_behind.is_empty() {
        out.push(Attention {
            tone: "warn",
            text: format!(
                "{} {} not have the master's current settings: {}.",
                plural(f.sync_behind.len(), "node", "nodes"),
                if f.sync_behind.len() == 1 {
                    "does"
                } else {
                    "do"
                },
                f.sync_behind.join(", ")
            ),
            href: card_url("settings-sync", ""),
        });
    }
    if has_nodes && f.nodes > 0 && f.resp_auth_ready == f.nodes && !c.cluster.enforce_response_auth
    {
        out.push(Attention {
            tone: "warn",
            text: "Every node can sign its replies, but the master does not require it yet.".into(),
            href: card_url("hardening", ""),
        });
    }
    if f.update_available {
        out.push(Attention {
            tone: "info",
            text: "A new Hyperion release is available.".into(),
            href: card_url("updates", ""),
        });
    }
    let errs = out.iter().filter(|a| a.tone == "err").count();
    let warns = out.iter().filter(|a| a.tone == "warn").count();
    let verdict = if errs > 0 {
        Verdict {
            tone: "err",
            text: "The settings could not be read".into(),
        }
    } else if warns > 0 {
        Verdict {
            tone: "warn",
            text: format!(
                "{} {} attention",
                plural(warns, "thing", "things"),
                if warns == 1 { "needs" } else { "need" }
            ),
        }
    } else {
        Verdict {
            tone: "ok",
            text: "Everything is set up".into(),
        }
    };
    (verdict, out)
}

/// One row per page, in sub-navigation order.
pub fn rows(f: &Facts, chrome: &Chrome) -> Vec<RowGroup> {
    chrome
        .nav()
        .into_iter()
        .map(|g| RowGroup {
            label: g.label,
            rows: g
                .items
                .into_iter()
                .map(|s| Row {
                    slug: s.slug,
                    title: s.title,
                    state: state_of(s.slug, f, chrome.has_nodes),
                })
                .collect(),
        })
        .collect()
}

fn state_of(slug: &str, f: &Facts, has_nodes: bool) -> String {
    let c = &f.config;
    let mut parts: Vec<String> = Vec::new();
    match slug {
        "panel" => {
            let host = c.cluster.panel_hostname.trim();
            parts.push(if host.is_empty() {
                "No domain — reached by IP".into()
            } else {
                format!("https://{host}:8443")
            });
            parts.push(if c.update_auto {
                "updates itself".into()
            } else {
                "updated by hand".into()
            });
            if f.update_available {
                parts.push("update available".into());
            }
        }
        "https" => {
            let contact = c.acme.contact_email.trim();
            parts.push(if contact.is_empty() {
                "No Let's Encrypt contact".into()
            } else {
                format!("Let's Encrypt contact {contact}")
            });
            let tpl = c.cluster.test_domain_template.trim();
            parts.push(if tpl.is_empty() {
                "no preview addresses".into()
            } else {
                format!("previews at {tpl}")
            });
        }
        "mail" => {
            parts.push(if c.email.enabled && !c.email.smtp_host.trim().is_empty() {
                format!(
                    "{} relays through {}:{}",
                    if has_nodes {
                        "The master"
                    } else {
                        "This server"
                    },
                    c.email.smtp_host.trim(),
                    c.email.smtp_port
                )
            } else {
                format!(
                    "{} has no relay and delivers directly",
                    if has_nodes {
                        "The master"
                    } else {
                        "This server"
                    }
                )
            });
            if has_nodes {
                parts.push("each node has its own".into());
            }
        }
        "alerts" => {
            parts.push(if c.slack.default_webhook_set {
                "Slack connected".into()
            } else {
                "Slack not connected".into()
            });
            let n = address_count(&c.email.default_to);
            parts.push(if n == 0 {
                "no administrator addresses".into()
            } else if !c.email.enabled {
                format!(
                    "{} (relay off, so no mail)",
                    plural(n, "administrator address", "administrator addresses")
                )
            } else {
                plural(n, "administrator address", "administrator addresses")
            });
        }
        "letters" => {
            parts.push(match f.letter_lang.as_str() {
                "cs" => "In Czech".into(),
                _ => "In English".into(),
            });
            parts.push(if f.letters_rewritten == 0 {
                "built-in wording".into()
            } else {
                format!(
                    "{} rewritten",
                    plural(f.letters_rewritten, "sentence", "sentences")
                )
            });
            // Subjects too: an older subject template wins over the editor
            // just as a body does.
            let legacy = !super::page_letters::active_legacy(&c.notifications).is_empty();
            if legacy {
                parts.push("an older whole-letter override is active".into());
            }
        }
        "backups" => {
            parts.push(
                match c.cluster.protection_mode.as_str() {
                    "backups" => "Archives only",
                    "snapshots" => "Snapshots only",
                    _ => "Archives and snapshots",
                }
                .into(),
            );
            let mut offsite: Vec<String> = Vec::new();
            if f.ftp_active {
                offsite.push(c.backup_remote.scheme.to_uppercase());
            }
            if f.s3_active > 0 {
                offsite.push(plural(f.s3_active, "S3 target", "S3 targets"));
            }
            parts.push(if offsite.is_empty() {
                "nothing off-site".into()
            } else {
                format!("off-site to {}", offsite.join(" + "))
            });
            parts.push(format!(
                "archives kept {} days",
                c.backup_retention.max_age_days
            ));
        }
        "access" => {
            parts.push(if c.cluster.enforce_admin_2fa {
                "2FA required for administrators".into()
            } else {
                "2FA optional".into()
            });
            parts.push(if c.cluster.audit_retention_days <= 0 {
                "audit log kept forever".into()
            } else {
                format!("audit log kept {} days", c.cluster.audit_retention_days)
            });
        }
        "bans" => {
            parts.push(match f.fail2ban_on {
                Some(true) => "Banning repeated failed logins".into(),
                Some(false) => "Brute-force scanner off".into(),
                None => "Scanner settings unreadable".into(),
            });
            parts.push(if f.geoip_installed {
                "GeoIP installed".into()
            } else {
                "no GeoIP database".into()
            });
        }
        "cluster" => {
            parts.push(plural(f.nodes, "worker node", "worker nodes"));
            if f.sync_known > 0 {
                parts.push(format!(
                    "{} of {} in sync",
                    f.sync_known - f.sync_behind.len(),
                    f.sync_known
                ));
            }
            let steps =
                c.cluster.enforce_worker_cert_pinning as u8 + c.cluster.enforce_response_auth as u8;
            parts.push(format!("hardening {steps} of 2"));
            if !c.cluster.master_accepts_hostings {
                parts.push("master takes no new sites".into());
            }
        }
        _ => {}
    }
    let mut s = parts.join(" · ");
    if let Some(first) = s.get(..1) {
        let up = first.to_uppercase();
        s.replace_range(..1, &up);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chrome(has_nodes: bool) -> Chrome {
        Chrome {
            section: "overview",
            title: "Settings",
            lead: "",
            can_edit: true,
            has_nodes,
            flash: None,
            flash_error: None,
        }
    }

    fn healthy() -> Facts {
        let mut f = Facts::default();
        f.config.cluster.panel_hostname = "panel.example.com".into();
        f.config.cluster.protection_mode = "both".into();
        f.ftp_active = true;
        f.config.slack.default_webhook_set = true;
        f.fail2ban_on = Some(true);
        f
    }

    #[test]
    fn a_set_up_install_needs_nothing() {
        let (v, a) = assess(&healthy(), false);
        assert_eq!(v.tone, "ok");
        assert!(
            a.is_empty(),
            "{:?}",
            a.iter().map(|a| &a.text).collect::<Vec<_>>()
        );
    }

    #[test]
    fn no_offsite_target_is_flagged_and_s3_counts_as_one() {
        let mut f = healthy();
        f.ftp_active = false;
        let (v, a) = assess(&f, false);
        assert_eq!(v.tone, "warn");
        assert!(a.iter().any(|a| a.href.ends_with("#offsite-targets")));
        f.s3_active = 1;
        let (v, _) = assess(&f, false);
        assert_eq!(v.tone, "ok");
    }

    #[test]
    fn snapshots_only_is_flagged_even_with_a_target() {
        let mut f = healthy();
        f.config.cluster.protection_mode = "snapshots".into();
        let (_, a) = assess(&f, false);
        assert!(a.iter().any(|a| a.href.ends_with("#protection-mode")));
    }

    #[test]
    fn alerts_to_nobody_is_flagged_and_an_address_fixes_it() {
        let mut f = healthy();
        f.config.slack.default_webhook_set = false;
        assert!(assess(&f, false)
            .1
            .iter()
            .any(|a| a.href.ends_with("#alert-recipients")));
        f.config.email.default_to = "ops@example.com, no-at-sign".into();
        // Addresses without the relay still reach nobody — and the fix is
        // the relay, not another address.
        assert!(assess(&f, false)
            .1
            .iter()
            .any(|a| a.href.ends_with("#smtp-relay")));
        f.config.email.enabled = true;
        assert_eq!(assess(&f, false).0.tone, "ok");
    }

    #[test]
    fn an_update_is_listed_but_not_counted() {
        let mut f = healthy();
        f.update_available = true;
        let (v, a) = assess(&f, false);
        assert_eq!(v.tone, "ok");
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].tone, "info");
    }

    #[test]
    fn cluster_problems_only_count_with_workers() {
        let mut f = healthy();
        f.nodes = 2;
        f.sync_known = 2;
        f.sync_behind = vec!["web-2".into()];
        f.resp_auth_ready = 2;
        let (v, a) = assess(&f, true);
        assert_eq!(v.tone, "warn");
        assert!(a.iter().any(|a| a.text.contains("web-2")));
        assert!(a.iter().any(|a| a.href.ends_with("#hardening")));
        let (v, _) = assess(&f, false);
        assert_eq!(v.tone, "ok");
    }

    #[test]
    fn unreadable_config_is_an_error() {
        let mut f = healthy();
        f.config_error = Some("boom".into());
        assert_eq!(assess(&f, false).0.tone, "err");
    }

    #[test]
    fn rows_follow_the_navigation_and_say_something() {
        let f = healthy();
        let groups = rows(&f, &chrome(false));
        let slugs: Vec<&str> = groups
            .iter()
            .flat_map(|g| g.rows.iter().map(|r| r.slug))
            .collect();
        assert!(!slugs.contains(&"cluster"));
        assert_eq!(slugs.first(), Some(&"panel"));
        for g in &groups {
            for r in &g.rows {
                assert!(!r.state.is_empty(), "{} has no state", r.slug);
                assert!(
                    r.state.starts_with(|c: char| !c.is_lowercase()),
                    "{}: {}",
                    r.slug,
                    r.state
                );
            }
        }
        assert!(rows(&f, &chrome(true))
            .iter()
            .any(|g| g.rows.iter().any(|r| r.slug == "cluster")));
    }

    #[test]
    fn address_count_splits_like_the_mailer() {
        assert_eq!(address_count(""), 0);
        assert_eq!(address_count("a@x.cz"), 1);
        assert_eq!(address_count("a@x.cz, b@y.cz;c@z.cz\nd@w.cz"), 4);
        assert_eq!(address_count("not-an-address"), 0);
    }
}
