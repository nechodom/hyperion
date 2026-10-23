//! Customer-letter catalogues and the expiry warning mail.

use super::*;

impl<A: AdapterPort + 'static> HostingService<A> {
    /// The catalogue to write THIS SITE's customer letters in.
    ///
    /// Resolution order, most specific first:
    ///   1. the site's own setting  (`hosting_kv`, `letters.lang`)
    ///   2. its care package's default (snapshotted onto the activation)
    ///   3. the cluster's `[letters] lang`
    ///
    /// Only the LANGUAGE is per-site. The operator's per-string overrides come
    /// from the cluster catalogue either way: those are the operator's wording,
    /// and a sentence they rewrote should read the same for every customer who
    /// gets that language.
    ///
    /// This is for letters the CUSTOMER reads. Operator alerts — Slack, the
    /// mail to every admin address — deliberately keep using
    /// [`Self::letter_catalog`]: one inbox holding messages in whichever
    /// language each site happens to be set to is worse than one language
    /// throughout.
    pub(super) async fn letter_catalog_for(&self, hosting_id: &HostingId) -> LetterCatalog {
        let mut cat = self.letter_catalog();
        let cluster_lang = cat.lang;
        // The site's own setting wins outright.
        if let Ok(Some(v)) = hyperion_state::hosting_kv::get(
            &self.pool,
            hosting_id.as_str(),
            Self::LETTER_LANG_KV_KEY,
        )
        .await
        {
            let v = v.trim();
            if !v.is_empty() {
                cat.lang = LetterLang::parse(v);
                drop_foreign_overrides(&mut cat, cluster_lang);
                return cat;
            }
        }
        // Otherwise the package's default, read from the ACTIVATION's snapshot
        // rather than the definition — definitions are master-only and this
        // runs on the node that owns the hosting.
        if let Ok(rows) = hyperion_state::packages::list_for_hosting(&self.pool, hosting_id).await {
            // Oldest active activation with an opinion. A site on two packages
            // is unusual; taking the first one that states a language is
            // deterministic, which is what matters.
            if let Some(l) = rows
                .iter()
                .map(|r| r.letters_lang.trim())
                .find(|l| !l.is_empty())
            {
                cat.lang = LetterLang::parse(l);
            }
        }
        drop_foreign_overrides(&mut cat, cluster_lang);
        cat
    }

    pub(super) fn letter_catalog(&self) -> LetterCatalog {
        read_letters_section(self.agent_config_path.as_deref())
    }

    /// Catalogue for OPERATOR-facing text (the notification bell, admin alerts),
    /// in `[letters] operator_lang` (default English) rather than the customer
    /// `lang`. So a Czech-customer operator keeps their own alerts in English.
    pub(super) fn operator_catalog(&self) -> LetterCatalog {
        let cat = self.letter_catalog();
        cat.in_language(cat.operator_lang)
    }

    /// Catalogue for the billing reminder. Follows `[letters] billing_lang`
    /// when set, else the customer `lang` — the reminder is about that
    /// customer's invoice, so it defaults to their language, not the operator's.
    pub(super) fn billing_catalog(&self) -> LetterCatalog {
        let cat = self.letter_catalog();
        match cat.billing_lang {
            Some(l) => cat.in_language(l),
            None => cat,
        }
    }

    /// The operator's expiry-warning body template. Same empty-means-default
    /// rule — and the same per-node caveat — as `care_report_template`.
    pub(super) fn expiry_warning_template(&self) -> String {
        read_notifications_section(self.agent_config_path.as_deref()).expiry_warning_body_template
    }
}

/// Drop the operator's per-string overrides when this site reads a DIFFERENT
/// language than the one they were written in.
///
/// The overrides are one flat list with no language on them, because until
/// v0.61 there was only ever one language in play. Now a site can read Czech
/// while the cluster is English, and a sentence the operator rewrote was
/// written in the CLUSTER's language — so applying it to the other pack
/// produces a letter that is Czech in the places the operator touched and
/// English everywhere else. Half a translation is worse than none: the customer
/// cannot tell it is a bug, only that their hosting company writes badly.
///
/// So an override travels with the language it was authored in, and a site
/// reading the other one gets the pack, whole. The operator is told this in
/// Settings; the alternative — keying every override by language — is a real
/// feature and not something to fake here.
/// Withhold the operator's rewritten sentences from a letter in a different
/// language from the one they were written in.
///
/// The protection is real — an English sentence dropped into a Czech letter
/// reads as broken — but it may only act on a FACT. It used to act on a
/// guess: the overrides were taken to be in the cluster's `lang`, which
/// defaults to English, so on an install that never changed that default
/// every Czech site silently lost every sentence the operator had rewritten.
/// The preview went on showing the built-in letter whatever they saved.
///
/// So now: only when the operator has DECLARED the language their wording is
/// in, and it differs from the letter's, is anything withheld. Undeclared
/// means apply. Of the two ways this can be wrong, an English sentence
/// appearing in a Czech letter is visible and fixed in one setting; the
/// operator's own words disappearing without a trace is neither.
///
/// `_cluster_lang` is kept in the signature because every caller still has it
/// to hand; it is no longer evidence of anything.
pub(super) fn drop_foreign_overrides(cat: &mut LetterCatalog, _cluster_lang: LetterLang) {
    if let Some(written_in) = cat.overrides_lang {
        if cat.lang != written_in {
            cat.overrides.clear();
        }
    }
}

/// Whole days left until `expires_at`, as a CALENDAR difference in UTC —
/// the same calendar `fmt_mail_date` prints — never negative. Derived from
/// the clock rather than from the warning's own 30/7/1 offset: a tick that
/// runs late (agent down for a day) must state the days that are actually
/// left, not the ones the row was queued for.
///
/// It must be a calendar difference and not the duration floor
/// `(expires_at - now) / 86_400`: the scheduler queues the 1-day row at
/// `expires_at - 86_400` and fires it at `+δ` (δ up to one 5-minute tick),
/// so the floor collapses to 0 on every real send and the letter claims
/// "expires today" on the day BEFORE the date it goes on to print.
pub(super) fn expiry_days_left(expires_at: i64, now: i64) -> i64 {
    let day =
        |s: i64| chrono::DateTime::<chrono::Utc>::from_timestamp(s, 0).map(|dt| dt.date_naive());
    match (day(expires_at), day(now)) {
        (Some(exp), Some(now)) => (exp - now).num_days().max(0),
        _ => 0,
    }
}

/// Subject + body of the expiry warning. The recipient is the SITE OWNER,
/// not the operator, so it explains consequences rather than mechanics.
/// Pure (every time-dependent input is an argument) so the wording is
/// unit-testable without an SMTP relay.
///
/// The consequences it names are the ones the scheduler really queues, see
/// `reconcile_scheduled_rows`: suspend at `expires_at`, delete at
/// `expires_at + grace_days.max(1)` days — hence the same `.max(1)` here,
/// so the date in the letter is the date the action fires.
///
/// Empty (or whitespace-only) `body_template` ⇒ the built-in wording, byte
/// for byte. A custom one replaces the BODY only; the subject keeps the
/// "[Hyperion] … expires in N days" shape the customer's mail rules and
/// our own `/emails` list key off.
///
/// Every date/day-count placeholder is pre-worded ("expires today",
/// "30 days", "1 day"), so a custom letter cannot invent a negative
/// countdown, mis-plural a single day, or name a delete date other than
/// the one `reconcile_scheduled_rows` actually queued. Unknown `{tokens}`
/// are left verbatim rather than dropped — see `render_template`.
#[allow(clippy::too_many_arguments)]
pub(super) fn expiry_warning_mail_with(
    cat: &LetterCatalog,
    domain: &str,
    expires_at: i64,
    grace_days: i64,
    now: i64,
    body_template: &str,
    subject_template: &str,
) -> (String, String) {
    let (days_left, fields) = expiry_fields(cat, domain, expires_at, grace_days, now);
    let subject_fields = expiry_subject_fields(cat, days_left, &fields);
    let subject_args: Vec<(&str, &str)> = subject_fields
        .iter()
        .map(|(k, v)| (*k, v.as_str()))
        .collect();
    let body_args: Vec<(&str, &str)> = fields.iter().map(|(k, v)| (*k, v.as_str())).collect();
    // The subject takes the same placeholders as the body, so an operator who
    // translated the letter can translate the line the customer sees FIRST.
    // Empty falls back to the catalogue's, which is already in the letter's
    // language — and which takes the very same set, so a subject moved from
    // `[notifications]` into the catalogue renders as it did.
    let subject = if subject_template.trim().is_empty() {
        let id = if days_left == 0 {
            "expiry.subject.today"
        } else {
            "expiry.subject.days"
        };
        cat.render(id, &subject_args)
    } else {
        render_template(subject_template, &subject_args)
    };
    let template = if body_template.trim().is_empty() {
        cat.get("expiry.body").to_string()
    } else {
        body_template.to_string()
    };
    (subject, render_template(&template, &body_args))
}

/// Every placeholder the expiry warning's BODY fills, worded in `cat`'s
/// language, and the number of days left. Shared by the letter and by
/// [`expiry_warning_preview_fields`], so the Settings preview cannot drift
/// from what a customer receives.
pub(super) fn expiry_fields(
    cat: &LetterCatalog,
    domain: &str,
    expires_at: i64,
    grace_days: i64,
    now: i64,
) -> (i64, Vec<(&'static str, String)>) {
    let days_left = expiry_days_left(expires_at, now);
    let grace = grace_days.max(1);
    let days_unit = cat.plural("unit_day", days_left);
    let grace_unit = cat.plural("unit_day", grace);
    // Dates in the letter's own calendar words: `report_date` reads the
    // month names out of the catalogue, so a Czech letter no longer names
    // the month in English.
    let exp_date = report_date(cat, expires_at);
    let del_date = report_date(cat, expires_at + grace * 86_400);
    let when = if days_left == 0 {
        cat.get("expiry.when.today").to_string()
    } else {
        cat.render(
            "expiry.when.days",
            &[
                ("date", &exp_date),
                ("days", &days_left.to_string()),
                ("unit", days_unit),
            ],
        )
    };
    // Bare values beside the ready-made ones, for the same reason the care
    // report has them: `{days_left}` carries its own unit word, so a
    // translated letter writing "{days_left} dní" produced "5 days dní", and
    // `{when}` is a whole sentence that lands in the middle of a paragraph.
    // `{expires_at}` and `{delete_at}` spell the month; the ISO forms are
    // digits, which every language can read.
    let fields = vec![
        ("domain", domain.to_string()),
        ("expires_at", exp_date),
        ("days_left", format!("{days_left} {days_unit}")),
        // Already clamped with `.max(1)`, so the letter names the date the
        // delete is really queued for.
        ("grace_days", format!("{grace} {grace_unit}")),
        ("delete_at", del_date),
        ("when", when),
        ("days_left_count", days_left.to_string()),
        ("grace_days_count", grace.to_string()),
        ("expires_at_iso", iso_date(cat, expires_at)),
        ("delete_at_iso", iso_date(cat, expires_at + grace * 86_400)),
    ];
    (days_left, fields)
}

/// The expiry SUBJECT's placeholders: the body's, plus `{days}` and `{unit}`
/// (the bare count and its word), which the built-in subjects are written in.
pub(super) fn expiry_subject_fields(
    cat: &LetterCatalog,
    days_left: i64,
    body_fields: &[(&'static str, String)],
) -> Vec<(&'static str, String)> {
    let mut out = body_fields.to_vec();
    out.push(("days", days_left.to_string()));
    out.push(("unit", cat.plural("unit_day", days_left).to_string()));
    out
}

/// The sample a Settings preview shows for each expiry-warning
/// `{placeholder}` (subject placeholders included), as `(name, value)` pairs.
///
/// Built by the same code as the letter, in `cat`'s language, for a fixed
/// hosting — example.com, expiring 1 Sep 2026 with a 14-day grace — seen
/// `days_left` days before it expires (0 = on the day, which is when the
/// "expires today" wording and subject are used).
pub fn expiry_warning_preview_fields(
    cat: &LetterCatalog,
    days_left: i64,
) -> Vec<(&'static str, String)> {
    let expires_at = 1_788_220_800; // 2026-09-01 00:00 UTC
    let now = expires_at - days_left.max(0) * 86_400;
    let (left, fields) = expiry_fields(cat, "example.com", expires_at, 14, now);
    expiry_subject_fields(cat, left, &fields)
}

/// Which of the two possible bodies a customer letter was rendered from,
/// in the words the audit trail and the journal use.
///
/// Both renderers treat a blank template as "send the built-in letter", so
/// blank is tested exactly the way they test it — an operator template of
/// three spaces must not be reported as the operator's.
///
/// This exists because the answer is per NODE. The letters are rendered on
/// the node that owns the hosting (that is where the data is) from that
/// node's agent.toml, while Settings edits the master's copy and pushes it
/// out. A node that was unreachable at save time goes on sending the old
/// letter, and this string is what makes that legible after the fact
/// instead of leaving "which letter did this customer get" unanswerable.
pub(super) fn letter_origin(template: &str) -> &'static str {
    if template.trim().is_empty() {
        "built-in"
    } else {
        "operator (this node's agent.toml)"
    }
}

/// One bare e-mail address and nothing else: no whitespace or control
/// characters (so no CR/LF header injection), no list separators, no display
/// name or angle brackets, exactly one `@` with something on both sides.
pub(super) fn is_single_plain_address(s: &str) -> bool {
    if s.chars().any(|c| {
        c.is_whitespace() || c.is_control() || matches!(c, ',' | ';' | '<' | '>' | '"' | '(' | ')')
    }) {
        return false;
    }
    match s.split_once('@') {
        Some((local, domain)) => !local.is_empty() && domain.contains('.') && !domain.contains('@'),
        None => false,
    }
}

/// [`letter_origin`], counting the operator's catalogue wording too.
///
/// Since Settings edits the care report and expiry warning as catalogue
/// strings (`care.body`, `expiry.subject.days`, …) rather than as whole-letter
/// templates, a letter in the operator's own words usually has an EMPTY
/// template — so the template alone would record "built-in" for wording the
/// operator wrote. `cat` is the catalogue the letter was rendered with (the
/// site's language, overrides already dropped when they are in another
/// language), and `ids` the strings that frame this letter.
pub(super) fn letter_origin_with(
    template: &str,
    cat: &crate::letters::LetterCatalog,
    ids: &[&str],
) -> &'static str {
    if !template.trim().is_empty() {
        return letter_origin(template);
    }
    let rewritten = ids
        .iter()
        .any(|id| cat.overrides.get(*id).is_some_and(|v| !v.trim().is_empty()));
    if rewritten {
        "operator wording (this node's agent.toml)"
    } else {
        "built-in"
    }
}

/// The catalogue ids that frame the care report.
pub(super) const CARE_FRAME_IDS: &[&str] = &["care.subject", "care.body"];
/// The catalogue ids that frame the expiry warning.
pub(super) const EXPIRY_FRAME_IDS: &[&str] =
    &["expiry.subject.days", "expiry.subject.today", "expiry.body"];

/// Read the letter language and per-string overrides from `[letters]` in
/// agent.toml.
///
/// A missing file, section or key leaves the built-in English pack, so an
/// install that has never touched Settings sends exactly the letters it
/// always did. Unknown ids are DROPPED rather than kept: they can only come
/// from a hand-edited file or a string this version has removed, and either
/// way carrying them forward would put wording in a letter that nothing
/// renders.
pub(super) fn read_letters_section(cfg_path: Option<&std::path::Path>) -> LetterCatalog {
    let Some(path) = cfg_path else {
        return LetterCatalog::default();
    };
    let Ok(raw) = std::fs::read_to_string(path) else {
        return LetterCatalog::default();
    };
    letter_catalog_from_toml(&raw)
}

/// [`read_letters_section`] against an agent.toml already in memory.
///
/// The panel has the file open anyway (the Raw TOML tab), and building the
/// catalogue from that same text is what lets the Settings preview render
/// through the identical code path the mailer uses. A preview that agrees
/// with the letter only most of the time is worse than none.
pub fn letter_catalog_from_toml(raw: &str) -> LetterCatalog {
    let Ok(doc) = raw.parse::<toml_edit::DocumentMut>() else {
        return LetterCatalog::default();
    };
    let Some(section) = doc.get("letters").and_then(|s| s.as_table_like()) else {
        return LetterCatalog::default();
    };
    let lang = section
        .get("lang")
        .and_then(|v| v.as_str())
        .map(LetterLang::parse)
        .unwrap_or_default();
    let mut cat = LetterCatalog::new(lang);
    // Only an explicit declaration counts. Absent, empty or unrecognised all
    // leave it `None`, which `drop_foreign_overrides` reads as "unknown — do
    // not guess, and do not throw anything away".
    cat.overrides_lang = section
        .get("overrides_lang")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|v| matches!(v.to_ascii_lowercase().as_str(), "en" | "cs"))
        .map(LetterLang::parse);
    // Operator-facing language (bell + admin mail). Default English: the panel
    // is English, so an operator's own alerts should be too until they say
    // otherwise — separate from the customer `lang` above.
    cat.operator_lang = section
        .get("operator_lang")
        .and_then(|v| v.as_str())
        .map(LetterLang::parse)
        .unwrap_or_default();
    // Billing-reminder language. Absent ⇒ follow the customer `lang` (the
    // reminder is about that customer's invoice); an explicit en/cs pins it.
    cat.billing_lang = section
        .get("billing_lang")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|v| matches!(v.to_ascii_lowercase().as_str(), "en" | "cs"))
        .map(LetterLang::parse);
    for (key, item) in section.iter() {
        if matches!(
            key,
            "lang" | "overrides_lang" | "operator_lang" | "billing_lang"
        ) {
            continue;
        }
        let Some(text) = item.as_str() else { continue };
        if crate::letters::lookup(key).is_some() {
            // A <textarea> submits CRLF per the HTML spec; left alone those
            // would reach a plain-text mail body.
            cat.overrides
                .insert(key.to_string(), text.replace("\r\n", "\n"));
        }
    }
    cat
}
