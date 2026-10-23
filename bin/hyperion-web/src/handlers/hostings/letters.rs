//! Customer-letter language per hosting.

use super::*;

/// Pause or resume the HTTP brute-force scan for one hosting.
///
/// Writes the OWNING node's kv, and resolves that node EXPLICITLY — a
/// `.ok()`-to-None fallback (as the read panels use) would silently
/// retarget a lookup failure at the master, whose kv the scanner never
/// reads, leaving the operator with a toggle that lies. Surface the
/// error in the tile instead.
/// `POST /hostings/:id/letter-language` — which language THIS site's customer
/// letters are written in.
///
/// Dispatched to the OWNING node, not written here: the care report and the
/// expiry warning are rendered on the node that owns the hosting, reading that
/// node's `hosting_kv`. A master-only write would leave the panel showing
/// Czech while the customer kept receiving English, which is the hardest kind
/// of wrong to notice — nothing looks broken.
#[derive(Template)]
#[template(path = "_hosting_letter_lang_card.html")]
pub(super) struct LetterLangCardTpl {
    pub(super) selector: String,
    pub(super) csrf_token: String,
    /// What the site's own setting says: "", "en" or "cs".
    pub(super) chosen: String,
    /// The language actually in force once package and cluster are considered.
    pub(super) effective_label: String,
    /// Where that came from, in the operator's words.
    pub(super) source_note: String,
    pub(super) error: Option<String>,
}

/// `GET /hostings/:selector/letter-lang-panel` — the resolved letter language.
///
/// Read from the OWNING node: both the site's `hosting_kv` and its package
/// snapshot live there, which is also where the letter is rendered. Asking the
/// master would show whatever the master happens to hold and could disagree
/// with what the customer receives.
pub async fn get_letter_lang_panel(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Path(selector): Path<String>,
) -> Result<Response, AppError> {
    let sel =
        match require_manage_for_selector(&state, &ctx, &selector, Capability::HostingEditConfig)
            .await
        {
            Ok(s) => s,
            Err(r) => return Ok(r),
        };
    let csrf_token = crate::handlers::session_csrf_token(&state, &ctx);
    let (detail, owner) = match find_hosting_anywhere(&state, sel).await {
        Ok(v) => v,
        Err(e) => {
            return Ok(Html(
                LetterLangCardTpl {
                    selector,
                    csrf_token,
                    chosen: String::new(),
                    effective_label: "unknown".into(),
                    source_note: "the owning node could not be reached".into(),
                    error: Some(e.to_string()),
                }
                .render()?,
            )
            .into_response())
        }
    };
    // One HostingKvList, the same way the brute-force card reads its own key:
    // there is no single-key RPC, and adding one for this would be a wire
    // change for a page that already fetches this table elsewhere.
    let chosen = match crate::dispatcher::dispatch_to_node(
        &state,
        owner.as_deref(),
        Request::HostingKvList {
            hosting_id: detail.id.as_str().to_string(),
        },
    )
    .await
    {
        // `Some("")` = the node answered and holds no setting.
        // `None`      = the node did not answer.
        //
        // Collapsing the two into "" made the card state "inherited — no care
        // package on this site states a language" about a node it never
        // reached: a positive claim about state that was not read, which is the
        // one thing this project refuses everywhere else.
        Ok(RpcResponse::HostingKvList(v)) => Some(
            v.into_iter()
                .find(|(k, _)| k == "letters.lang")
                .map(|(_, val)| val.trim().to_string())
                .unwrap_or_default(),
        ),
        _ => None,
    };
    let Some(chosen) = chosen else {
        return Ok(Html(
            LetterLangCardTpl {
                selector,
                csrf_token,
                chosen: String::new(),
                effective_label: "unknown".into(),
                source_note: "the node that owns this site did not answer, so what \
                              language it writes in could not be read"
                    .into(),
                error: Some(
                    "Saving below still works — it writes to the owning node — but \
                     the current value shown is not from that node."
                        .into(),
                ),
            }
            .render()?,
        )
        .into_response());
    };
    let label = |l: &str| match l {
        "cs" => "Čeština",
        _ => "English",
    };
    let (effective_label, source_note) = if !chosen.trim().is_empty() {
        (
            label(chosen.trim()).to_string(),
            "set on this site".to_string(),
        )
    } else {
        // Fall through the same order the letter itself does. Reported rather
        // than guessed: the operator needs to know whether editing the package
        // would change this site or not.
        // The activation snapshot, read from the OWNING node for the same
        // reason as the kv above: that is the copy the letter is rendered from.
        let pkg = match crate::dispatcher::dispatch_to_node(
            &state,
            owner.as_deref(),
            Request::PackageActivations {
                sel: HostingSelector::Id(detail.id.clone()),
                history: false,
            },
        )
        .await
        {
            Ok(RpcResponse::PackageActivations(v)) => Some(
                v.into_iter()
                    .map(|p| p.letters_lang.trim().to_string())
                    .find(|l| !l.is_empty())
                    .unwrap_or_default(),
            ),
            _ => None,
        };
        let Some(pkg) = pkg else {
            return Ok(Html(
                LetterLangCardTpl {
                    selector,
                    csrf_token,
                    chosen,
                    effective_label: "unknown".into(),
                    source_note: "this site has no language of its own, and its care \
                                  packages could not be read from the owning node"
                        .into(),
                    error: None,
                }
                .render()?,
            )
            .into_response());
        };
        let pkg = pkg.as_str();
        if pkg.is_empty() {
            (
                "the panel setting".to_string(),
                "inherited — no care package on this site states a language".to_string(),
            )
        } else {
            (
                label(pkg).to_string(),
                "inherited from this site's care package".to_string(),
            )
        }
    };
    Ok(Html(
        LetterLangCardTpl {
            selector,
            csrf_token,
            chosen,
            effective_label,
            source_note,
            error: None,
        }
        .render()?,
    )
    .into_response())
}

pub async fn post_letter_language(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<LetterLanguageForm>,
) -> Result<Response, AppError> {
    // Same gate the other per-site config writes use: manage on THIS hosting,
    // resolved through the selector so a tenant cannot address someone else's.
    let sel = match require_manage_for_selector(
        &state,
        &ctx,
        &form.selector,
        Capability::HostingEditConfig,
    )
    .await
    {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let (detail, owner) = match find_hosting_anywhere(&state, sel).await {
        Ok(v) => v,
        Err(e) => {
            return Ok(Redirect::to(&format!(
                "/hostings?flash_error={}",
                urlencoding(&e.to_string())
            ))
            .into_response())
        }
    };

    // Only the two the pack knows, plus empty for "no opinion". Anything else
    // would be stored and then resolve to English silently.
    let value = match form.lang.trim() {
        "en" => "en",
        "cs" => "cs",
        _ => "",
    };
    let saved = crate::dispatcher::dispatch_to_node(
        &state,
        owner.as_deref(),
        Request::HostingKvSet {
            hosting_id: detail.id.as_str().to_string(),
            key: "letters.lang".into(),
            value: value.into(),
        },
    )
    .await;
    let flash = match saved {
        Ok(RpcResponse::HostingKvSet) => match value {
            "" => {
                "letter language cleared — this site follows its care package, or the panel setting"
                    .to_string()
            }
            l => format!("customer letters for this site will be written in {l}"),
        },
        Ok(RpcResponse::Error(e)) => format!("the owning node refused the change: {e}"),
        Ok(_) => "unexpected response from the owning node".into(),
        Err(e) => format!("could not reach the owning node: {e}"),
    };
    Ok(Redirect::to(&format!(
        "/hostings/{}?flash={}#emails",
        detail.id.as_str(),
        urlencoding(&flash)
    ))
    .into_response())
}

#[derive(Deserialize)]
pub struct LetterLanguageForm {
    #[serde(default)]
    pub _csrf: String,
    pub selector: String,
    #[serde(default)]
    pub lang: String,
}
