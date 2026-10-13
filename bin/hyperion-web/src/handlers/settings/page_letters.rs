//! `GET /settings/letters` — what site owners receive from you: the letters'
//! language, the care report and the expiry warning, every other sentence,
//! the e-mail logo and where the report's Core Web Vitals come from.
//!
//! Also `POST /settings/letters/adopt-legacy`, which retires the older
//! whole-letter templates.
//!
//! # One editor per letter
//!
//! The care report and the expiry warning used to be editable in two places:
//! a whole-letter template in `[notifications]`
//! (`care_report_subject_template` and friends) and the catalogue strings
//! `care.subject`, `care.body`, `expiry.subject.*`, `expiry.body` in
//! `[letters]`. The renderers use a non-blank template INSTEAD of the
//! catalogue and ignore the letter's language, so a Czech rewrite went to
//! English customers too, and an edit in the other place did nothing. The
//! page now edits the catalogue only; while an older template is still in
//! force the Letters card says so and offers to move it into the editor or
//! discard it.

use super::chrome::{self, Chrome, PageQuery};
use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::state::SharedState;
use askama::Template;
use axum::extract::{Query, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Form;
use hyperion_core::letters::{LetterCatalog, LetterLang};
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use hyperion_state::capabilities::Capability;
use hyperion_types::{AgentConfigView, NotificationTemplatesView};
use serde::Deserialize;
use std::collections::BTreeMap;

/// The catalogue strings the Letters card edits. The Sentences card leaves
/// them out: the same field twice on one page, in two forms, would leave the
/// operator guessing which one a save keeps.
pub(super) const EDITOR_IDS: &[&str] = &[
    "care.subject",
    "care.body",
    "expiry.subject.days",
    "expiry.subject.today",
    "expiry.body",
];

/// One older whole-letter template in `[notifications]`, and the catalogue
/// string that now holds the same part of the letter.
pub(super) struct Legacy {
    /// The `[notifications]` key.
    pub key: &'static str,
    /// The catalogue id "Move into the editor" writes it to.
    pub id: &'static str,
    /// Which letter, and which part of it.
    pub letter: &'static str,
    pub part: &'static str,
}

/// Every older template. The expiry warning had ONE subject for every day;
/// the catalogue has one while days remain and one for the day it expires,
/// and the older subject moves into the first.
pub(super) const LEGACY: &[Legacy] = &[
    Legacy {
        key: "care_report_subject_template",
        id: "care.subject",
        letter: "care report",
        part: "subject",
    },
    Legacy {
        key: "care_report_body_template",
        id: "care.body",
        letter: "care report",
        part: "body",
    },
    Legacy {
        key: "expiry_warning_subject_template",
        id: "expiry.subject.days",
        letter: "expiry warning",
        part: "subject",
    },
    Legacy {
        key: "expiry_warning_body_template",
        id: "expiry.body",
        letter: "expiry warning",
        part: "body",
    },
];

fn legacy_value<'a>(n: &'a NotificationTemplatesView, key: &str) -> &'a str {
    match key {
        "care_report_subject_template" => &n.care_report_subject_template,
        "care_report_body_template" => &n.care_report_body_template,
        "expiry_warning_subject_template" => &n.expiry_warning_subject_template,
        "expiry_warning_body_template" => &n.expiry_warning_body_template,
        _ => "",
    }
}

/// The older templates in force: the non-blank ones, which is exactly the
/// test the renderers apply (`trim().is_empty()` ⇒ use the catalogue).
pub(super) fn active_legacy(n: &NotificationTemplatesView) -> Vec<&'static Legacy> {
    LEGACY
        .iter()
        .filter(|l| !legacy_value(n, l.key).trim().is_empty())
        .collect()
}

/// "the care report body and the expiry warning subject", "the care report
/// subject and body, and the expiry warning body".
fn legacy_summary(active: &[&Legacy]) -> String {
    let mut parts: Vec<String> = Vec::new();
    for letter in ["care report", "expiry warning"] {
        let has = |part: &str| active.iter().any(|l| l.letter == letter && l.part == part);
        match (has("subject"), has("body")) {
            (true, true) => parts.push(format!("the {letter} subject and body")),
            (true, false) => parts.push(format!("the {letter} subject")),
            (false, true) => parts.push(format!("the {letter} body")),
            (false, false) => {}
        }
    }
    if parts.iter().any(|p| p.contains(" and ")) {
        parts.join(", and ")
    } else {
        parts.join(" and ")
    }
}

/// An older expiry subject in the catalogue's own tokens. The catalogue
/// subject takes every body token too, so this changes nothing on a current
/// agent; it lets a node still running an agent from before that render the
/// two tokens a subject actually uses, and lets the fork guard recognise a
/// subject that is the built-in one spelled the old way.
fn expiry_subject_in_catalogue_tokens(s: &str) -> String {
    s.replace("{days_left_count}", "{days}")
        .replace("{days_left}", "{days} {unit}")
}

/// What "Move into the editor" writes to `[letters]`: each older template in
/// force under its catalogue id, normalised and fork-guarded exactly like a
/// save from the editor — so a template that only ever repeated the built-in
/// letter is stored as "no override", and follows each letter's language
/// from now on instead of pinning one.
///
/// The older expiry subject was ALSO the subject of the last notice, on the
/// day a hosting expires; the catalogue splits that into its own id. Unless
/// the operator already wrote that one, it gets the moved subject too, so the
/// most important notice keeps the operator's wording and language.
pub(super) fn moved_fields(
    n: &NotificationTemplatesView,
    lang: LetterLang,
    today_subject_written: bool,
) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for l in active_legacy(n) {
        let raw = legacy_value(n, l.key);
        let raw = if l.id == "expiry.subject.days" {
            expiry_subject_in_catalogue_tokens(raw)
        } else {
            raw.to_string()
        };
        let stored = super::letter_value_to_store(l.id, &raw, lang);
        // Only real wording: a template that merely repeated the built-in
        // "expires in N days" must not become the expiry-day subject.
        if l.id == "expiry.subject.days" && !today_subject_written && !stored.is_empty() {
            out.insert("expiry.subject.today".to_string(), stored.clone());
        }
        out.insert(l.id.to_string(), stored);
    }
    out
}

/// What retiring the older templates writes to `[notifications]`: all four
/// keys EMPTY. The agent stores an empty string as `key = ""`, which every
/// reader treats as absent (the renderers fall back to the catalogue), and
/// the settings sync carries the empty value to every node.
fn cleared_fields() -> BTreeMap<String, String> {
    LEGACY
        .iter()
        .map(|l| (l.key.to_string(), String::new()))
        .collect()
}

/// One field of the Letters editor.
pub struct EditorField {
    /// The operator's wording, empty when there is none (the built-in is sent).
    pub current: String,
    /// The pack's wording in the letter language: the field's placeholder,
    /// and what "Start from the built-in" puts in.
    pub built_in: &'static str,
}

impl EditorField {
    fn of(cat: &LetterCatalog, id: &str) -> Self {
        Self {
            current: cat.overrides.get(id).cloned().unwrap_or_default(),
            built_in: hyperion_core::letters::lookup(id)
                .map(|s| s.built_in(cat.lang))
                .unwrap_or(""),
        }
    }

    fn is_set(&self) -> bool {
        !self.current.trim().is_empty()
    }
}

/// One fold of the Sentences editor: the strings that belong to the same
/// part of a letter.
pub struct SentenceGroup {
    pub name: &'static str,
    /// How many of them carry the operator's own wording.
    pub rewritten: usize,
    pub strings: Vec<SentenceRow>,
}

/// One translatable string, as the editor needs it.
///
/// `built_in` is shown as the field's placeholder rather than its value, so
/// an untouched string stays EMPTY in the form and therefore empty in
/// agent.toml. That is what keeps "I have not customised this" different
/// from "I have pinned this to today's wording": the first follows the
/// built-in pack when it improves, the second does not.
pub struct SentenceRow {
    pub id: &'static str,
    /// `id` with its dots made safe for an element id.
    pub dom_id: String,
    pub note: &'static str,
    pub built_in: &'static str,
    pub current: String,
    /// Multi-line strings get a <textarea>, one-liners an <input>.
    pub multiline: bool,
}

/// Every catalogue string but the Letters card's, grouped in table order.
fn sentence_groups(cat: &LetterCatalog) -> Vec<SentenceGroup> {
    hyperion_core::letters::groups()
        .into_iter()
        .map(|g| {
            let strings: Vec<SentenceRow> = hyperion_core::letters::STRINGS
                .iter()
                .filter(|s| s.group == g && !EDITOR_IDS.contains(&s.id))
                .map(|s| {
                    let built_in = s.built_in(cat.lang);
                    SentenceRow {
                        id: s.id,
                        dom_id: format!("ls-{}", s.id.replace('.', "-")),
                        note: s.note,
                        built_in,
                        current: cat.overrides.get(s.id).cloned().unwrap_or_default(),
                        multiline: built_in.contains('\n') || built_in.len() > 60,
                    }
                })
                .collect();
            SentenceGroup {
                name: g,
                rewritten: strings
                    .iter()
                    .filter(|s| !s.current.trim().is_empty())
                    .count(),
                strings,
            }
        })
        .filter(|g| !g.strings.is_empty())
        .collect()
}

/// A preview sample as a JSON object for the page's script. Emitted with
/// `|safe` into a <script> block, so the one sequence that could end it has
/// to go; the samples are our own wording, but that must stay true when a
/// section ever quotes markup. A failure only means no sample: the
/// placeholders then render as themselves, visibly "no sample".
fn sample_json(fields: Vec<(&'static str, String)>) -> String {
    let map: BTreeMap<&str, String> = fields.into_iter().collect();
    serde_json::to_string(&map)
        .unwrap_or_else(|_| "{}".to_string())
        .replace("</", "<\\/")
}

#[derive(Template)]
#[template(path = "settings_letters.html")]
struct LettersTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    chrome: Chrome,
    csrf_token: String,
    config: AgentConfigView,
    config_error: Option<String>,
    /// agent.toml could not be read, so the wording shown is the pack's.
    toml_error: Option<String>,
    // Languages.
    lang: &'static str,
    lang_label: &'static str,
    overrides_lang: &'static str,
    billing_lang: &'static str,
    // Letters.
    care_subject: EditorField,
    care_body: EditorField,
    expiry_subject: EditorField,
    expiry_subject_today: EditorField,
    expiry_body: EditorField,
    /// Does each letter carry the operator's own wording anywhere?
    care_set: bool,
    expiry_set: bool,
    /// The older templates in force, and in words.
    legacy: Vec<&'static Legacy>,
    legacy_names: String,
    care_sample_json: String,
    expiry_sample_json: String,
    expiry_today_sample_json: String,
    // Sentences.
    groups: Vec<SentenceGroup>,
    sentences_rewritten: usize,
    // Logo.
    email_logo_set: bool,
}

pub async fn get_letters(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Query(q): Query<PageQuery>,
) -> Result<Response, AppError> {
    if !ctx.can(Capability::SettingsManage) {
        return Ok(Redirect::to("/").into_response());
    }
    let (chrome, _nodes) = chrome::chrome(&state, &ctx, "letters", &q).await;
    let (config_res, logo_res, toml_res) = tokio::join!(
        hyperion_rpc_client::call(&state.agent_socket, Request::AgentConfigView),
        hyperion_rpc_client::call(&state.agent_socket, Request::EmailLogoGet),
        // The letter language and every override, from the SAME file the
        // mailer reads (and the export and import use).
        tokio::fs::read_to_string("/etc/hyperion/agent.toml"),
    );
    let (config, config_error) = super::config_or_default(config_res);
    let (cat, toml_error) = match toml_res {
        Ok(raw) => (hyperion_core::service::letter_catalog_from_toml(&raw), None),
        Err(e) => (LetterCatalog::default(), Some(e.to_string())),
    };
    let email_logo_set = matches!(logo_res, Ok(RpcResponse::EmailLogoGet(Some(_))));
    let legacy = active_legacy(&config.notifications);
    let groups = sentence_groups(&cat);
    let sentences_rewritten = groups.iter().map(|g| g.rewritten).sum();
    let lang_opt = |l: Option<LetterLang>| l.map(LetterLang::as_str).unwrap_or("");
    let care_subject = EditorField::of(&cat, "care.subject");
    let care_body = EditorField::of(&cat, "care.body");
    let expiry_subject = EditorField::of(&cat, "expiry.subject.days");
    let expiry_subject_today = EditorField::of(&cat, "expiry.subject.today");
    let expiry_body = EditorField::of(&cat, "expiry.body");
    let care_set = care_subject.is_set() || care_body.is_set();
    let expiry_set =
        expiry_subject.is_set() || expiry_subject_today.is_set() || expiry_body.is_set();
    let tpl = LettersTpl {
        username: &ctx.username,
        user_initial: crate::handlers::user_initial(&ctx.username),
        active: "settings",
        css_version: crate::handlers::css_version(),
        htmx_version: crate::handlers::htmx_version(),
        chrome,
        csrf_token: crate::handlers::session_csrf_token(&state, &ctx),
        config_error,
        toml_error,
        lang: cat.lang.as_str(),
        lang_label: cat.lang.label(),
        overrides_lang: lang_opt(cat.overrides_lang),
        billing_lang: lang_opt(cat.billing_lang),
        care_subject,
        care_body,
        expiry_subject,
        expiry_subject_today,
        expiry_body,
        care_set,
        expiry_set,
        legacy_names: legacy_summary(&legacy),
        legacy,
        // Rendered by the very functions that build a customer's letter, so
        // the preview cannot drift from what is sent. The care sample leaves
        // availability unmeasured on purpose: that is the case worth reading
        // inside your own wording before a customer does.
        care_sample_json: sample_json(hyperion_core::service::care_report_preview_fields(&cat)),
        expiry_sample_json: sample_json(hyperion_core::service::expiry_warning_preview_fields(
            &cat, 7,
        )),
        expiry_today_sample_json: sample_json(
            hyperion_core::service::expiry_warning_preview_fields(&cat, 0),
        ),
        groups,
        sentences_rewritten,
        email_logo_set,
        config,
    };
    Ok(Html(tpl.render()?).into_response())
}

#[derive(Deserialize)]
pub struct AdoptLegacyForm {
    /// `move` — into the editor; `discard` — drop them.
    #[serde(default)]
    pub mode: String,
}

/// `POST /settings/letters/adopt-legacy` — retire the older whole-letter
/// templates in `[notifications]`, Owner only.
///
/// `mode=move` first writes each one in force into its catalogue string
/// (fork-guarded like any editor save), and only once that has landed clears
/// the templates — in that order, so a failure in between leaves the older
/// template still winning rather than a letter with neither. `mode=discard`
/// only clears them. Both sections reach the other nodes through the settings
/// sync; nodes it cannot update get them pushed now.
pub async fn post_adopt_legacy(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<AdoptLegacyForm>,
) -> Result<Response, AppError> {
    const CARD: &str = "customer-letters";
    if !ctx.is_super_admin() {
        return Ok(chrome::back_with_error(
            CARD,
            "Only an Owner can change the letters.",
        ));
    }
    let moving = match form.mode.as_str() {
        "move" => true,
        "discard" => false,
        _ => {
            return Ok(chrome::back_with_error(
                CARD,
                "Unknown action — nothing was changed.",
            ))
        }
    };
    let notifications =
        match hyperion_rpc_client::call(&state.agent_socket, Request::AgentConfigView).await {
            Ok(RpcResponse::AgentConfigView(c)) => c.notifications,
            Ok(RpcResponse::Error(e)) => {
                return Ok(chrome::back_with_error(
                    CARD,
                    &format!("The agent's settings could not be read ({e}) — nothing was changed."),
                ))
            }
            Ok(_) => {
                return Ok(chrome::back_with_error(
                    CARD,
                    "Unexpected answer from the agent — nothing was changed.",
                ))
            }
            Err(e) => {
                return Ok(chrome::back_with_error(
                    CARD,
                    &format!("The agent did not answer ({e}) — nothing was changed."),
                ))
            }
        };
    let active = active_legacy(&notifications);
    if active.is_empty() {
        return Ok(chrome::back_with_flash(
            CARD,
            "No older template is in force any more — nothing to do.",
        ));
    }
    let what = legacy_summary(&active);

    let moved = if moving {
        let cat = super::current_letter_catalogue().await;
        let today_written = cat
            .overrides
            .get("expiry.subject.today")
            .is_some_and(|v| !v.trim().is_empty());
        let fields = moved_fields(&notifications, cat.lang, today_written);
        if let Err(e) = config_update(&state, "letters", &fields).await {
            return Ok(chrome::back_with_error(
                CARD,
                &format!("Could not write the editor's wording ({e}) — nothing was changed."),
            ));
        }
        Some(fields)
    } else {
        None
    };
    let cleared = cleared_fields();
    if let Err(e) = config_update(&state, "notifications", &cleared).await {
        return Ok(chrome::back_with_error(
            CARD,
            &if moved.is_some() {
                format!(
                    "The wording is in the editor now, but the older template could not be \
                     removed ({e}), so it still wins. Try again."
                )
            } else {
                format!("The older template could not be removed ({e}).")
            },
        ));
    }

    // Both sections are synced: kick the sync rather than wait for its next
    // pass, and push straight to any node it cannot update (an older agent).
    state.cluster_sync.kick();
    let mut failed: Vec<String> = Vec::new();
    if let Some(f) = &moved {
        if let Err(e) = super::push_to_unsynced_nodes(&state, "letters", f.clone()).await {
            failed.extend(e);
        }
    }
    // Moving: a node the sync cannot update keeps its older template. It
    // may have refused the wording above (an agent older than the catalogue),
    // and clearing the template there would leave its customers with the
    // built-in letter — neither the old wording nor the new. The template
    // still wins on such a node, so its letters stay what they were.
    if !moving {
        if let Err(e) = super::push_to_unsynced_nodes(&state, "notifications", cleared).await {
            failed.extend(e);
        }
    }
    super::restart_agent_soon();

    if !failed.is_empty() {
        failed.sort();
        failed.dedup();
        return Ok(chrome::back_with_error(
            CARD,
            &format!(
                "Done on this master, but {} did not take it: {}. Sites on {} keep the \
                 older letter until it is updated — the Nodes page shows which nodes have the \
                 master's settings.",
                if failed.len() == 1 {
                    "one node"
                } else {
                    "some nodes"
                },
                failed.join("; "),
                if failed.len() == 1 { "it" } else { "them" },
            ),
        ));
    }
    let is_master = state.deployment_mode.read().await.as_str() == "master";
    let has_nodes = !chrome::enrolled_nodes(&state).await.is_empty();
    let mut msg = if moving {
        format!("Moved {what} into the editor; the older template is gone")
    } else {
        format!("Discarded the older template for {what}")
    };
    msg.push_str(" — the agent restarts in about 5 s");
    if is_master && has_nodes {
        msg.push_str("; the other nodes get it within a minute");
    }
    msg.push('.');
    if moving && active.iter().any(|l| l.id == "expiry.subject.days") {
        let both = moved
            .as_ref()
            .is_some_and(|f| f.contains_key("expiry.subject.today"));
        msg.push_str(if both {
            " The expiry subject is used both while days remain and on the day a \
             hosting expires; edit either in the Expiry warning letter."
        } else {
            " The expiry subject applies while days remain; your own subject for the \
             day a hosting expires is kept."
        });
    }
    Ok(chrome::back_with_flash(CARD, &msg))
}

/// One `AgentConfigUpdate` on the master, as a plain result.
async fn config_update(
    state: &SharedState,
    section: &str,
    fields: &BTreeMap<String, String>,
) -> Result<(), String> {
    match hyperion_rpc_client::call(
        &state.agent_socket,
        Request::AgentConfigUpdate {
            section: section.to_string(),
            fields: fields.clone().into(),
        },
    )
    .await
    {
        Ok(RpcResponse::AgentConfigUpdate) => Ok(()),
        Ok(RpcResponse::Error(e)) => Err(e.to_string()),
        Ok(_) => Err("unexpected answer from the agent".into()),
        Err(e) => Err(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn templates(
        care_subject: &str,
        care_body: &str,
        expiry_subject: &str,
        expiry_body: &str,
    ) -> NotificationTemplatesView {
        NotificationTemplatesView {
            care_report_subject_template: care_subject.into(),
            care_report_body_template: care_body.into(),
            expiry_warning_subject_template: expiry_subject.into(),
            expiry_warning_body_template: expiry_body.into(),
            ..Default::default()
        }
    }

    #[test]
    fn every_older_template_moves_into_a_string_the_editor_shows() {
        for l in LEGACY {
            assert!(
                hyperion_core::letters::lookup(l.id).is_some(),
                "{} → {}: not a catalogue id",
                l.key,
                l.id
            );
            assert!(
                EDITOR_IDS.contains(&l.id),
                "{} moves into {}, which the Letters card does not show",
                l.key,
                l.id
            );
        }
        for id in EDITOR_IDS {
            assert!(
                hyperion_core::letters::lookup(id).is_some(),
                "{id}: not a catalogue id"
            );
        }
        // And the empty view the agent reports when none is set holds none.
        assert!(active_legacy(&NotificationTemplatesView::default()).is_empty());
    }

    #[test]
    fn each_template_lands_on_its_own_id() {
        let n = templates("S {domain}", "B {attacks}", "ES {domain}", "EB {when}");
        let f = moved_fields(&n, LetterLang::En, false);
        assert_eq!(
            f.get("care.subject").map(String::as_str),
            Some("S {domain}")
        );
        assert_eq!(f.get("care.body").map(String::as_str), Some("B {attacks}"));
        assert_eq!(
            f.get("expiry.subject.days").map(String::as_str),
            Some("ES {domain}")
        );
        assert_eq!(f.get("expiry.body").map(String::as_str), Some("EB {when}"));
        // The older expiry subject also covered the expiry day.
        assert_eq!(
            f.get("expiry.subject.today").map(String::as_str),
            Some("ES {domain}")
        );
        assert_eq!(f.len(), 5, "nothing else is written: {f:?}");
    }

    /// The renderers never used a blank template, so moving one would write
    /// an empty override over wording the operator may have in the editor.
    #[test]
    fn a_blank_template_is_not_moved() {
        let n = templates("", "  \n", "", "Hello {domain}");
        let f = moved_fields(&n, LetterLang::En, false);
        assert_eq!(f.keys().collect::<Vec<_>>(), vec!["expiry.body"]);
        assert_eq!(
            active_legacy(&n).iter().map(|l| l.key).collect::<Vec<_>>(),
            vec!["expiry_warning_body_template"]
        );
    }

    /// A template that only repeated the built-in letter is stored as "no
    /// override" — same fork guard as the editor, CRLF included — so it
    /// follows each letter's language from now on.
    #[test]
    fn a_template_equal_to_the_built_in_is_stored_empty() {
        let built_in = |id: &str, lang| {
            hyperion_core::letters::lookup(id)
                .expect("id")
                .built_in(lang)
                .to_string()
        };
        for lang in [LetterLang::En, LetterLang::Cs] {
            let body = built_in("care.body", lang).replace('\n', "\r\n");
            let n = templates("", &body, "", &built_in("expiry.body", lang));
            let f = moved_fields(&n, lang, false);
            assert_eq!(f.get("care.body").map(String::as_str), Some(""), "{lang:?}");
            assert_eq!(
                f.get("expiry.body").map(String::as_str),
                Some(""),
                "{lang:?}"
            );
        }
        // The CZECH built-in moved on an ENGLISH install is the operator's
        // wording there, and is kept (normalised to LF).
        let cs = built_in("care.body", LetterLang::Cs).replace('\n', "\r\n");
        let f = moved_fields(&templates("", &cs, "", ""), LetterLang::En, false);
        assert_eq!(
            f.get("care.body").map(String::as_str),
            Some(built_in("care.body", LetterLang::Cs).as_str())
        );
    }

    /// The older expiry subject spoke `{days_left}`; the catalogue's built-in
    /// speaks `{days} {unit}`. Same words either way — and the built-in
    /// spelled the old way is recognised as the built-in.
    #[test]
    fn the_expiry_subject_moves_in_the_catalogues_tokens() {
        let n = templates(
            "",
            "",
            "Za {days_left_count} dní: {domain} ({days_left})",
            "",
        );
        let f = moved_fields(&n, LetterLang::Cs, false);
        assert_eq!(
            f.get("expiry.subject.days").map(String::as_str),
            Some("Za {days} dní: {domain} ({days} {unit})")
        );
        let old_spelling = "[Hyperion] Hosting for {domain} expires in {days_left}";
        let f = moved_fields(&templates("", "", old_spelling, ""), LetterLang::En, false);
        assert_eq!(f.get("expiry.subject.days").map(String::as_str), Some(""));
        assert!(
            !f.contains_key("expiry.subject.today"),
            "the built-in wording is not the operator's expiry-day subject"
        );
    }

    /// The older subject was also the expiry-day subject; it stays that,
    /// unless the operator already wrote their own for that day.
    #[test]
    fn a_moved_expiry_subject_also_covers_the_expiry_day() {
        let n = templates("", "", "Vaše hosting {domain} brzy vyprší", "");
        let f = moved_fields(&n, LetterLang::Cs, false);
        assert_eq!(
            f.get("expiry.subject.today").map(String::as_str),
            Some("Vaše hosting {domain} brzy vyprší")
        );
        let f = moved_fields(&n, LetterLang::Cs, true);
        assert!(!f.contains_key("expiry.subject.today"));
    }

    #[test]
    fn clearing_empties_exactly_the_four_templates() {
        let c = cleared_fields();
        assert_eq!(c.len(), 4);
        assert!(c.values().all(String::is_empty));
        for l in LEGACY {
            assert!(c.contains_key(l.key));
            // Each one is a key the settings sync carries, so the empty value
            // reaches every node.
            assert!(hyperion_core::cluster_sync::is_synced_key(
                "notifications",
                l.key
            ));
        }
    }

    #[test]
    fn the_warning_names_what_is_in_force() {
        let names = |n: NotificationTemplatesView| legacy_summary(&active_legacy(&n));
        assert_eq!(
            names(templates("s", "b", "", "")),
            "the care report subject and body"
        );
        assert_eq!(names(templates("", "b", "", "")), "the care report body");
        assert_eq!(
            names(templates("", "b", "s", "")),
            "the care report body and the expiry warning subject"
        );
        assert_eq!(
            names(templates("s", "", "s", "b")),
            "the care report subject, and the expiry warning subject and body"
        );
    }

    #[test]
    fn the_sentences_editor_leaves_out_the_letters_editor_strings() {
        let groups = sentence_groups(&LetterCatalog::default());
        let ids: Vec<&str> = groups
            .iter()
            .flat_map(|g| g.strings.iter().map(|s| s.id))
            .collect();
        for id in EDITOR_IDS {
            assert!(!ids.contains(id), "{id} is on both cards");
        }
        assert_eq!(
            ids.len() + EDITOR_IDS.len(),
            hyperion_core::letters::STRINGS.len(),
            "every other string is on the Sentences card"
        );
        assert!(groups.iter().all(|g| !g.strings.is_empty()));
        // Element ids stay unique once the dots are replaced.
        let mut dom: Vec<&str> = groups
            .iter()
            .flat_map(|g| g.strings.iter().map(|s| s.dom_id.as_str()))
            .collect();
        let n = dom.len();
        dom.sort_unstable();
        dom.dedup();
        assert_eq!(dom.len(), n);
    }

    #[test]
    fn a_sentence_count_ignores_blank_overrides() {
        let mut cat = LetterCatalog::default();
        cat.overrides.insert("list_sep".into(), " / ".into());
        cat.overrides.insert("unit_day".into(), "  ".into());
        let total: usize = sentence_groups(&cat).iter().map(|g| g.rewritten).sum();
        assert_eq!(total, 1);
    }

    /// The fork guard every letters save goes through.
    #[test]
    fn the_shared_fork_guard_normalises_then_compares() {
        let s = hyperion_core::letters::lookup("expiry.body").expect("id");
        let crlf = s.built_in(LetterLang::En).replace('\n', "\r\n");
        assert_eq!(
            super::super::letter_value_to_store("expiry.body", &crlf, LetterLang::En),
            ""
        );
        assert_eq!(
            super::super::letter_value_to_store("expiry.body", "Hi\r\nthere", LetterLang::En),
            "Hi\nthere"
        );
    }

    #[test]
    fn a_sample_cannot_close_its_script_tag() {
        let j = sample_json(vec![("x", "</script><b>".into())]);
        assert!(!j.contains("</"), "{j}");
        assert!(serde_json::from_str::<serde_json::Value>(&j).is_ok());
    }
}
