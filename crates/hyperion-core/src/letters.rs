//! Every word the two CUSTOMER LETTERS can say, in one place, so an
//! operator can translate ALL of it.
//!
//! # Why this module exists
//!
//! The care report is assembled from six sections, and each section picks
//! one of three to seven wordings depending on what was actually measured
//! ("ATTACKS BLOCKED: 12" vs "…: not monitored" vs "…: 12 (since 15 Jun)").
//! Those branches cannot be expressed in a flat `{placeholder}` template,
//! so for a long time the only way to get a section into a letter was the
//! `{attacks}`-style placeholder that expands to the whole rendered
//! English paragraph. An operator who translated the letter got their own
//! Czech prose with English blocks embedded in it, and no field anywhere
//! to fix them: the wording was in Rust.
//!
//! Bare-value placeholders (`{attacks_count}` and friends) softened that
//! but could not solve it, because a bare value cannot carry the branch.
//! "—" is the honest value when nothing was measured, and the sentence
//! that explains WHY there is a dash is exactly the sentence that was
//! unreachable.
//!
//! So the branches themselves became data. Every literal the letters can
//! emit is a keyed string here with an English default and a Czech
//! translation, and the operator may override any of them from Settings.
//! Nothing customer-facing is left in Rust.
//!
//! # The rule that survives translation
//!
//! Wording is the operator's; WHICH wording is used is not. The branch is
//! still chosen by the same measured/unmeasured tests as before, so a
//! translated letter cannot promote "not monitored" into a percentage —
//! it can only say "nesledováno" instead of "not monitored". That is the
//! property the whole report is built on and the one thing an editable
//! string must not be able to take away.

use std::collections::BTreeMap;

/// Which built-in pack a letter starts from.
///
/// Not a locale in the CLDR sense — it selects one column of
/// [`STRINGS`] and one plural rule, nothing more. Adding a language is
/// adding a column, which is deliberately more work than adding a
/// config value: a half-translated pack would ship English sentences to
/// paying customers under a Czech heading.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LetterLang {
    #[default]
    En,
    Cs,
}

impl LetterLang {
    pub fn as_str(self) -> &'static str {
        match self {
            LetterLang::En => "en",
            LetterLang::Cs => "cs",
        }
    }

    /// Unknown values fall back to English rather than erroring: a typo in
    /// `agent.toml` must not stop a customer's report going out.
    pub fn parse(s: &str) -> LetterLang {
        match s.trim().to_ascii_lowercase().as_str() {
            "cs" | "cz" | "cesky" | "česky" => LetterLang::Cs,
            _ => LetterLang::En,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            LetterLang::En => "English",
            LetterLang::Cs => "Čeština",
        }
    }

    /// Which form of a `one|few|many` string a count selects.
    ///
    /// English has two forms and Czech three (1 / 2–4 / 0 and 5+), which
    /// is the whole reason plural units are strings here rather than a
    /// `plural(n, "day", "days")` call in Rust: a two-form helper cannot
    /// produce "2 dny" and "5 dní" from the same pair.
    fn plural_index(self, n: i64) -> usize {
        let n = n.unsigned_abs();
        match self {
            LetterLang::En => usize::from(n != 1),
            LetterLang::Cs => match n {
                1 => 0,
                2..=4 => 1,
                _ => 2,
            },
        }
    }
}

/// One translatable string.
///
/// Both languages sit on the same line so a new string cannot be added in
/// English alone — `every_string_is_translated` fails the build if `cs` is
/// ever left empty, which is the failure mode that would otherwise reach a
/// customer as a paragraph of English in the middle of a Czech letter.
pub struct LetterString {
    pub id: &'static str,
    /// Which card the Settings editor files it under.
    pub group: &'static str,
    /// What the string is for, and which `{tokens}` it may use — shown
    /// beside the field so an operator is not guessing.
    pub note: &'static str,
    pub en: &'static str,
    pub cs: &'static str,
}

impl LetterString {
    pub fn built_in(&self, lang: LetterLang) -> &'static str {
        match lang {
            LetterLang::En => self.en,
            LetterLang::Cs => self.cs,
        }
    }
}

/// Look one string up in the table.
pub fn lookup(id: &str) -> Option<&'static LetterString> {
    STRINGS.iter().find(|s| s.id == id)
}

/// The groups, in the order the Settings editor should show them.
pub fn groups() -> Vec<&'static str> {
    let mut out: Vec<&'static str> = Vec::new();
    for s in STRINGS {
        if !out.contains(&s.group) {
            out.push(s.group);
        }
    }
    out
}

/// A language plus the operator's per-string overrides: everything the two
/// letters need in order to be rendered in somebody's own words.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LetterCatalog {
    pub lang: LetterLang,
    /// `id -> replacement`. Only ids present in [`STRINGS`] are ever
    /// stored (the settings write path rejects the rest), so an override
    /// left behind by a removed string is inert rather than a panic.
    pub overrides: BTreeMap<String, String>,
}

impl LetterCatalog {
    pub fn new(lang: LetterLang) -> Self {
        Self {
            lang,
            overrides: BTreeMap::new(),
        }
    }

    /// The operator's wording, else the pack's.
    ///
    /// A blank override reads as "no override" for the same reason a blank
    /// letter template does: clearing a field in the UI is how you go back
    /// to the built-in wording, and a letter with an empty paragraph in it
    /// is nobody's intent.
    pub fn get<'a>(&'a self, id: &'a str) -> &'a str {
        if let Some(v) = self.overrides.get(id) {
            if !v.trim().is_empty() {
                return v.as_str();
            }
        }
        match lookup(id) {
            Some(s) => s.built_in(self.lang),
            // An id that is not in the table is a programming error, not an
            // operator one. Returning the id keeps it visible in the letter
            // (and in the Settings preview) instead of silently deleting a
            // paragraph, which is the same contract `render_template` gives
            // an unknown `{token}`.
            None => id,
        }
    }

    /// [`Self::get`] with `{token}` substitution.
    pub fn render(&self, id: &str, args: &[(&str, &str)]) -> String {
        render_template(self.get(id), args)
    }

    /// Pick the plural form of a `one|few|many` string for `n`.
    ///
    /// Forms past the end fall back to the LAST one, so a pack that gives
    /// two forms to a three-form language degrades to "2 dní" rather than
    /// to an empty word.
    pub fn plural<'a>(&'a self, id: &'a str, n: i64) -> &'a str {
        let raw = self.get(id);
        let want = self.lang.plural_index(n);
        let mut last = raw;
        for (i, form) in raw.split('|').enumerate() {
            last = form;
            if i == want {
                return form;
            }
        }
        last
    }

    /// Thousands-grouped integer in this language's convention: `34,500`
    /// in English, `34 500` in Czech.
    pub fn group_int(&self, n: i64) -> String {
        let sep = self.get("num_group_sep");
        let digits = n.unsigned_abs().to_string();
        let mut out = String::with_capacity(digits.len() * 2);
        if n < 0 {
            out.push('-');
        }
        for (i, ch) in digits.chars().enumerate() {
            // Group from the LEFT by counting how many digits remain.
            if i > 0 && (digits.len() - i) % 3 == 0 {
                out.push_str(sep);
            }
            out.push(ch);
        }
        out
    }

    /// Re-point a Rust-formatted decimal at this language's separator.
    /// Czech writes "34,5 MB" and "99,93 %"; a full stop there reads as a
    /// different number to the customer being invoiced.
    pub fn decimal(&self, formatted: &str) -> String {
        let sep = self.get("num_decimal_sep");
        if sep == "." {
            return formatted.to_string();
        }
        formatted.replacen('.', sep, 1)
    }

    /// The twelve month abbreviations, from the single comma-separated
    /// `date_months` string. Short of twelve, the missing tail falls back
    /// to the pack's own list rather than printing an empty month.
    pub fn months(&self) -> Vec<String> {
        let names: Vec<String> = self
            .get("date_months")
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if names.len() == 12 {
            return names;
        }
        lookup("date_months")
            .map(|s| s.built_in(self.lang))
            .unwrap_or("")
            .split(',')
            .map(|s| s.trim().to_string())
            .collect()
    }

    /// Every id whose wording this catalog actually changes — what the
    /// per-node parity check compares, and what gets written to
    /// `agent.toml`.
    pub fn effective_overrides(&self) -> BTreeMap<String, String> {
        self.overrides
            .iter()
            .filter(|(k, v)| !v.trim().is_empty() && lookup(k).is_some())
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }
}

/// Substitute `{key}` tokens in `tmpl` with the matching value. Single
/// pass (substituted values are NOT re-scanned, so a value containing
/// `{time}` won't itself get expanded), UTF-8 safe, and unknown `{tokens}`
/// are left verbatim so an operator's typo is visible in the output
/// rather than silently dropped.
pub fn render_template(tmpl: &str, fields: &[(&str, &str)]) -> String {
    let mut out = String::with_capacity(tmpl.len() + 32);
    let mut rest = tmpl;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        if let Some(close) = after.find('}') {
            let key = &after[..close];
            if let Some((_, val)) = fields.iter().find(|(k, _)| *k == key) {
                out.push_str(val);
                rest = &after[close + 1..];
                continue;
            }
        }
        // Not a closed, known placeholder — emit the literal '{' and move on.
        out.push('{');
        rest = after;
    }
    out.push_str(rest);
    out
}

/// Every literal the two customer letters can emit.
///
/// Adding a string here is the ONLY way to put words in a letter. The
/// `care_section_*` renderers hold no prose of their own any more — they
/// choose an id and hand it the measured values, which is what keeps
/// "which wording" a decision of the code and "what it says" a decision of
/// the operator.
///
/// `note` is shown beside the field in Settings. It names the `{tokens}`
/// the string may use, because an operator cannot be expected to guess
/// them and a typo'd token survives into the customer's letter verbatim.
pub static STRINGS: &[LetterString] = &[
    // ── Numbers, dates and units ───────────────────────────────────────
    //
    // Not decoration. A Czech letter that writes "34,500 requests" has
    // said thirty-four and a half, and a customer reading an invoice
    // beside it will believe the smaller number.
    LetterString {
        id: "num_group_sep",
        group: "Numbers and dates",
        note: "Thousands separator. English groups with a comma, Czech with a space.",
        en: ",",
        cs: " ",
    },
    LetterString {
        id: "num_decimal_sep",
        group: "Numbers and dates",
        note: "Decimal separator, used by sizes and percentages.",
        en: ".",
        cs: ",",
    },
    LetterString {
        id: "date_months",
        group: "Numbers and dates",
        note: "Twelve month abbreviations, comma-separated, January first.",
        en: "Jan,Feb,Mar,Apr,May,Jun,Jul,Aug,Sep,Oct,Nov,Dec",
        cs: "led,úno,bře,dub,kvě,čvn,čvc,srp,zář,říj,lis,pro",
    },
    LetterString {
        id: "date_fmt",
        group: "Numbers and dates",
        note: "How one date is written. Tokens: {day} {month} {year}.",
        en: "{day} {month} {year}",
        cs: "{day}. {month} {year}",
    },
    LetterString {
        id: "date_time_fmt",
        group: "Numbers and dates",
        note: "Date with a clock time. Tokens: {date} {time}. Keep the zone — the customer may not be in UTC.",
        en: "{date} {time} UTC",
        cs: "{date} {time} UTC",
    },
    LetterString {
        id: "date_unknown",
        group: "Numbers and dates",
        note: "Stands in for a date the server could not make sense of.",
        en: "unknown date",
        cs: "neznámé datum",
    },
    LetterString {
        id: "time_unknown",
        group: "Numbers and dates",
        note: "Stands in for a time the server could not make sense of.",
        en: "unknown time",
        cs: "neznámý čas",
    },
    LetterString {
        id: "unit_day",
        group: "Numbers and dates",
        note: "Plural forms of \"day\", separated by |. English takes two (1 / other), Czech three (1 / 2–4 / 5+).",
        en: "day|days",
        cs: "den|dny|dní",
    },
    LetterString {
        id: "unit_check",
        group: "Numbers and dates",
        note: "Plural forms of \"check\" (an uptime probe), separated by |.",
        en: "check|checks",
        cs: "kontrola|kontroly|kontrol",
    },
    LetterString {
        id: "unit_request",
        group: "Numbers and dates",
        note: "Plural forms of \"request\" (one page, image or file load), separated by |.",
        en: "request|requests",
        cs: "požadavek|požadavky|požadavků",
    },
    LetterString {
        id: "unit_update",
        group: "Numbers and dates",
        note: "Plural forms of \"update\", separated by |.",
        en: "update|updates",
        cs: "aktualizace|aktualizace|aktualizací",
    },
    LetterString {
        id: "unit_copy",
        group: "Numbers and dates",
        note: "Plural forms of \"copy\" (a stored backup), separated by |.",
        en: "copy|copies",
        cs: "kopie|kopie|kopií",
    },
    LetterString {
        id: "unit_finding",
        group: "Numbers and dates",
        note: "Plural forms of \"finding\" (something the file check flagged), separated by |.",
        en: "finding|findings",
        cs: "nález|nálezy|nálezů",
    },
    LetterString {
        id: "list_sep",
        group: "Numbers and dates",
        note: "Joins items listed inside one sentence.",
        en: ", ",
        cs: ", ",
    },
    // ── The care report's own frame ────────────────────────────────────
    LetterString {
        id: "care.subject",
        group: "Care report — frame",
        note: "Subject line. Tokens: {domain} {period_start} {period_end} {days} {days_count}.",
        en: "Care report for {domain} ({period_start} – {period_end})",
        cs: "Report údržby pro {domain} ({period_start} – {period_end})",
    },
    LetterString {
        id: "care.body",
        group: "Care report — frame",
        note: "The whole letter. Section tokens {attacks} {updates} {traffic} {uptime} {backups} {integrity} expand to the wording set below; bare values are {domain} {period_start} {period_end} {days} and the *_count / *_iso forms.",
        en: "CARE REPORT\n\
             Site:    {domain}\n\
             Period:  {period_start} – {period_end} ({days})\n\
             \n\
             Here is what happened on your site during this period. We only quote\n\
             figures we actually measured. Where something was not being measured,\n\
             we say so — rather than print a zero that would claim something other\n\
             than \"we were not looking\".\n\
             \n\
             {attacks}\n\
             \n\
             {updates}\n\
             \n\
             {traffic}\n\
             \n\
             {uptime}\n\
             \n\
             {backups}\n\
             \n\
             {integrity}\n\
             \n\
             --\n\
             You receive this report because {domain} is on a care plan.\n\
             The figures come straight from the server the site runs on; times are UTC.\n\
             If anything here needs explaining, just reply to this e-mail.\n",
        cs: "REPORT ÚDRŽBY\n\
             Web:     {domain}\n\
             Období:  {period_start} – {period_end} ({days})\n\
             \n\
             Zde je přehled toho, co se na vašem webu za toto období událo. Uvádíme\n\
             pouze hodnoty, které jsme skutečně naměřili. Pokud jsme něco neměřili,\n\
             výslovně to píšeme — místo nuly, která by tvrdila něco jiného než\n\
             „nedívali jsme se\".\n\
             \n\
             {attacks}\n\
             \n\
             {updates}\n\
             \n\
             {traffic}\n\
             \n\
             {uptime}\n\
             \n\
             {backups}\n\
             \n\
             {integrity}\n\
             \n\
             --\n\
             Tento report dostáváte, protože web {domain} má aktivní plán údržby.\n\
             Údaje pocházejí přímo ze serveru, na kterém web běží; časy jsou v UTC.\n\
             Pokud potřebujete cokoliv vysvětlit, stačí odpovědět na tento e-mail.\n",
    },
    // ── Attacks ────────────────────────────────────────────────────────
    //
    // Four wordings, and which one is used is decided by the data, never
    // by the template. `none` is the branch that must never be allowed to
    // read as a quiet month: no protection was running, so nobody knows.
    LetterString {
        id: "care.attacks.none",
        group: "Care report — attacks",
        note: "Attack protection was not running at all. Must not read as \"zero attacks\".",
        en: "ATTACKS BLOCKED: not monitored\n  \
             Automatic attack protection was not running on this server during\n  \
             the period. We do not print a zero here — it would mean nobody was\n  \
             watching.",
        cs: "ZABLOKOVANÉ ÚTOKY: nesledováno\n  \
             Automatická ochrana proti útokům na tomto serveru v daném období\n  \
             neběžela. Neuvádíme zde nulu — znamenala by, že se nikdo nedíval.",
    },
    LetterString {
        id: "care.attacks.zero",
        group: "Care report — attacks",
        note: "Protection ran the whole period and never had to act.",
        en: "ATTACKS BLOCKED: 0\n  \
             Protection ran for the whole period and never had to step in. That\n  \
             is good news, not a missing figure.",
        cs: "ZABLOKOVANÉ ÚTOKY: 0\n  \
             Ochrana běžela po celé období a ani jednou nemusela zasáhnout. To je\n  \
             dobrá zpráva, ne chybějící údaj.",
    },
    LetterString {
        id: "care.attacks.some",
        group: "Care report — attacks",
        note: "Attacks were blocked across the whole period. Token: {count}.",
        en: "ATTACKS BLOCKED: {count}\n  \
             That is how many times we cut off an address that kept trying to\n  \
             guess an admin password or otherwise abuse the site. A blocked\n  \
             address cannot reach the site at all for several hours.",
        cs: "ZABLOKOVANÉ ÚTOKY: {count}\n  \
             Tolikrát jsme odstřihli adresu, která se opakovaně pokoušela uhodnout\n  \
             administrátorské heslo nebo web jinak zneužít. Zablokovaná adresa se\n  \
             na web několik hodin vůbec nedostane.",
    },
    LetterString {
        id: "care.attacks.since",
        group: "Care report — attacks",
        note: "Protection started part-way through the period, so the count is not a period total. Tokens: {count} {since}.",
        en: "ATTACKS BLOCKED: {count} (since {since})\n  \
             Automatic attack protection has been watching this site since\n  \
             {since}, not for the whole period, so this figure covers only that\n  \
             part of it. We cannot say what reached the site beforehand.",
        cs: "ZABLOKOVANÉ ÚTOKY: {count} (od {since})\n  \
             Automatická ochrana tento web hlídá od {since}, tedy ne po celé\n  \
             období, takže tento údaj pokrývá jen jeho část. Co se na web dostalo\n  \
             předtím, nedokážeme říct.",
    },
    // ── Updates ────────────────────────────────────────────────────────
    LetterString {
        id: "care.updates.none",
        group: "Care report — updates",
        note: "The operational log does not span the period, so no count can be given.",
        en: "PLUGIN AND THEME UPDATES: not determined\n  \
             Our operational records do not cover this whole period, so we\n  \
             cannot give you an exact count. We will not pass an incomplete\n  \
             number off as a complete one.",
        cs: "AKTUALIZACE PLUGINŮ A ŠABLON: nezjištěno\n  \
             Naše provozní záznamy nepokrývají celé toto období, takže vám\n  \
             nemůžeme dát přesný počet. Neúplné číslo nebudeme vydávat za úplné.",
    },
    LetterString {
        id: "care.updates.zero",
        group: "Care report — updates",
        note: "Nothing needed updating in the period.",
        en: "PLUGIN AND THEME UPDATES: 0\n  \
             There was nothing to apply — plugins and themes were up to date\n  \
             throughout the period.",
        cs: "AKTUALIZACE PLUGINŮ A ŠABLON: 0\n  \
             Nebylo co instalovat — pluginy i šablony byly po celé období\n  \
             aktuální.",
    },
    LetterString {
        id: "care.updates.some",
        group: "Care report — updates",
        note: "Updates were applied. Tokens: {count} {unit}. The figure covers plugins and themes only — say so.",
        en: "PLUGIN AND THEME UPDATES: {count}\n  \
             We applied {count} {unit} to the site. We count only the ones that\n  \
             actually installed. WordPress core updates are not in this figure —\n  \
             we do not track those separately yet.",
        cs: "AKTUALIZACE PLUGINŮ A ŠABLON: {count}\n  \
             Na webu jsme provedli {count} {unit}. Počítáme jen ty, které se\n  \
             skutečně nainstalovaly. Aktualizace jádra WordPressu v tomto čísle\n  \
             nejsou — ty zatím nesledujeme zvlášť.",
    },
    // ── Traffic ────────────────────────────────────────────────────────
    LetterString {
        id: "care.traffic.none",
        group: "Care report — traffic",
        note: "Traffic was not being measured. \"0 requests\" would claim nobody visited.",
        en: "TRAFFIC: not measured\n  \
             Traffic measurement was not running for this site during the\n  \
             period. \"0 requests\" would claim nobody visited the site, and we\n  \
             do not know that.",
        cs: "NÁVŠTĚVNOST: neměřeno\n  \
             Měření návštěvnosti pro tento web v daném období neběželo. „0\n  \
             požadavků\" by tvrdilo, že web nikdo nenavštívil, a to nevíme.",
    },
    LetterString {
        id: "care.traffic.head",
        group: "Care report — traffic",
        note: "Opening line of the traffic section. Tokens: {requests} {unit} {sent}.",
        en: "TRAFFIC: {requests} {unit}, {sent} sent\n  \
             A request is one load of a page, an image or a file.",
        cs: "NÁVŠTĚVNOST: {requests} {unit}, odesláno {sent}\n  \
             Jeden požadavek je jedno načtení stránky, obrázku nebo souboru.",
    },
    LetterString {
        id: "care.traffic.received",
        group: "Care report — traffic",
        note: "Appended when inbound bytes are known. Token: {received}.",
        en: "\n  Data received: {received}.",
        cs: "\n  Přijatá data: {received}.",
    },
    LetterString {
        id: "care.traffic.received_unknown",
        group: "Care report — traffic",
        note: "Appended when the server does not log inbound bytes. A zero there would be ambiguous.",
        en: "\n  The server does not record how much data was received, so we do\n  \
             not quote it.",
        cs: "\n  Server nezaznamenává, kolik dat bylo přijato, proto tento údaj\n  \
             neuvádíme.",
    },
    LetterString {
        id: "care.traffic.disk_peak",
        group: "Care report — traffic",
        note: "Peak disk use during the period. Token: {disk}.",
        en: "\n  Peak disk use during the period: {disk}.",
        cs: "\n  Nejvyšší obsazení disku za období: {disk}.",
    },
    LetterString {
        id: "care.traffic.complete",
        group: "Care report — traffic",
        note: "The figures cover every day of the period. Tokens: {counted} {total} {unit}.",
        en: "\n  These figures cover the whole period ({counted} of {total} {unit}).",
        cs: "\n  Tyto údaje pokrývají celé období ({counted} z {total} {unit}).",
    },
    LetterString {
        id: "care.traffic.partial",
        group: "Care report — traffic",
        note: "Sampling had a gap. Tokens: {counted} {total} {unit}. Say \"may have been higher\", not \"was\" — the unmeasured days may have been quiet.",
        en: "\n  Note: these figures cover only {counted} of the period's {total} {unit}\n  \
             — the rest was not measured, so real traffic may have been higher.",
        cs: "\n  Pozn.: tyto údaje pokrývají jen {counted} z {total} {unit} tohoto\n  \
             období — zbytek jsme neměřili, takže skutečná návštěvnost mohla být\n  \
             vyšší.",
    },
    // ── Availability ───────────────────────────────────────────────────
    //
    // THE section this whole design exists for. With no samples there is
    // no percentage, and "100 %" for a site nobody watched is the exact
    // lie the report must never tell — in any language.
    LetterString {
        id: "care.uptime.none",
        group: "Care report — availability",
        note: "Uptime checks were not running. Never replace this with a percentage.",
        en: "AVAILABILITY: not monitored (uptime checks were not active)\n  \
             We were not checking this site regularly during the period, so we\n  \
             cannot say whether it stayed reachable. A figure of 100 % would be\n  \
             invented.",
        cs: "DOSTUPNOST: nesledováno (kontroly dostupnosti nebyly aktivní)\n  \
             Web jsme v tomto období pravidelně nekontrolovali, takže nemůžeme\n  \
             říct, zda byl stále dostupný. Údaj 100 % by byl vymyšlený.",
    },
    LetterString {
        id: "care.uptime.perfect",
        group: "Care report — availability",
        note: "Every check answered. Tokens: {pct} {samples} {unit}.",
        en: "AVAILABILITY: {pct} ({samples} {unit}, no outage)\n  \
             We checked the site automatically and it answered every time.",
        cs: "DOSTUPNOST: {pct} ({samples} {unit}, žádný výpadek)\n  \
             Web jsme automaticky kontrolovali a pokaždé odpověděl.",
    },
    LetterString {
        id: "care.uptime.failures",
        group: "Care report — availability",
        note: "Some checks failed. Tokens: {pct} {samples} {unit} {failures} {failures_unit}.",
        en: "AVAILABILITY: {pct} ({samples} {unit}, {failures} of them failed)\n  \
             The site did not answer on {failures} {failures_unit}. One or two failed\n  \
             checks are usually a brief outage or a restart; if they repeat, we\n  \
             look into it.",
        cs: "DOSTUPNOST: {pct} ({samples} {unit}, z toho {failures} neúspěšných)\n  \
             Web neodpověděl při {failures} {failures_unit}. Jedna dvě neúspěšné\n  \
             kontroly bývají krátký výpadek nebo restart; pokud se opakují,\n  \
             prověříme to.",
    },
    LetterString {
        id: "care.uptime.partial",
        group: "Care report — availability",
        note: "Checks ran on only part of the period, so the percentage describes that part. Tokens: {counted} {total} {total_unit} {counted_unit}.",
        en: "\n  Note: checks ran on only {counted} of the period's {total} {total_unit},\n  \
             so this percentage describes those {counted_unit} — not the whole period.",
        cs: "\n  Pozn.: kontroly proběhly jen {counted} z {total} {total_unit} tohoto\n  \
             období, takže procento popisuje těchto {counted} {counted_unit} — ne\n  \
             celé období.",
    },
    // ── Backups ────────────────────────────────────────────────────────
    //
    // Three genuinely different states, and the middle one is the alarming
    // one: a site that DOES take backups and took none this period must not
    // read like a site that never had any.
    LetterString {
        id: "care.backups.none",
        group: "Care report — backups",
        note: "Backups were never switched on for this site. Different from \"0 this period\".",
        en: "BACKUPS: not monitored\n  \
             Not a single backup has ever run for this site — automatic backups\n  \
             were never switched on for it. \"0 backups\" would look like a\n  \
             failure; this is the state where backups were never enabled.",
        cs: "ZÁLOHY: nesledováno\n  \
             Pro tento web nikdy neproběhla ani jedna záloha — automatické zálohy\n  \
             pro něj nebyly nikdy zapnuté. „0 záloh\" by vypadalo jako selhání;\n  \
             tohle je stav, kdy zálohy nebyly nikdy zapnuté.",
    },
    LetterString {
        id: "care.backups.zero",
        group: "Care report — backups",
        note: "Backups ARE configured and none ran. This is a problem and should read like one.",
        en: "BACKUPS: 0 in this period\n  \
             This site does have backups configured, but none ran during the\n  \
             period. That needs looking into — please get in touch.",
        cs: "ZÁLOHY: 0 za toto období\n  \
             Tento web má zálohy nastavené, ale v tomto období žádná neproběhla.\n  \
             To je potřeba prověřit — ozvěte se nám prosím.",
    },
    LetterString {
        id: "care.backups.some",
        group: "Care report — backups",
        note: "Backups were stored. Tokens: {count} {unit}.",
        en: "BACKUPS: {count}\n  \
             We stored {count} complete {unit} of the site (files and database).",
        cs: "ZÁLOHY: {count}\n  \
             Uložili jsme {count} kompletní {unit} webu (soubory i databáze).",
    },
    LetterString {
        id: "care.backups.last",
        group: "Care report — backups",
        note: "Appended when a successful backup happened inside the period. Token: {when}.",
        en: "\n  Last successful backup: {when}.",
        cs: "\n  Poslední úspěšná záloha: {when}.",
    },
    LetterString {
        id: "care.backups.failed",
        group: "Care report — backups",
        note: "Appended when some attempts failed. Token: {count}.",
        en: "\n  Failed attempts: {count} (these retry automatically).",
        cs: "\n  Neúspěšné pokusy: {count} (opakují se automaticky).",
    },
    // ── File integrity and malware ─────────────────────────────────────
    //
    // "Clean" requires BOTH halves to have run. Zero malware hits from a
    // scanner that was never installed means "not looked for".
    LetterString {
        id: "care.integrity.none",
        group: "Care report — file integrity",
        note: "No file check ran at all. \"We did not look\" is not \"it is clean\".",
        en: "FILE INTEGRITY AND MALWARE: not checked\n  \
             No file check ran on the site during this period. So we cannot say\n  \
             it is clean — only that we did not look.",
        cs: "INTEGRITA SOUBORŮ A MALWARE: nekontrolováno\n  \
             V tomto období na webu neproběhla žádná kontrola souborů. Nemůžeme\n  \
             tedy říct, že je čistý — jen to, že jsme se nedívali.",
    },
    LetterString {
        id: "care.integrity.clean",
        group: "Care report — file integrity",
        note: "Both halves ran and found nothing. Token: {when}.",
        en: "FILE INTEGRITY AND MALWARE: nothing found\n  \
             Check on {when}: the WordPress files match what wordpress.org\n  \
             published, and the malware scan found nothing.",
        cs: "INTEGRITA SOUBORŮ A MALWARE: nic nenalezeno\n  \
             Kontrola {when}: soubory WordPressu odpovídají tomu, co vydala\n  \
             wordpress.org, a sken na malware nic nenašel.",
    },
    LetterString {
        id: "care.integrity.partial",
        group: "Care report — file integrity",
        note: "The check found nothing but only ran in part, so \"clean\" cannot be written. Token: {when}.",
        en: "FILE INTEGRITY AND MALWARE: only partly checked\n  \
             The check on {when} found nothing, but it only ran in part — so we\n  \
             cannot write \"clean\".",
        cs: "INTEGRITA SOUBORŮ A MALWARE: zkontrolováno jen zčásti\n  \
             Kontrola {when} nic nenašla, ale proběhla jen zčásti — nemůžeme tedy\n  \
             napsat „čisté\".",
    },
    LetterString {
        id: "care.integrity.findings",
        group: "Care report — file integrity",
        note: "The check flagged something. Tokens: {count} {unit} {when} {what}.",
        en: "FILE INTEGRITY AND MALWARE: {count} {unit}\n  \
             The check on {when} found: {what}.\n  \
             Not every finding means an attack — a hand-edited file looks the\n  \
             same. If you are unsure about a finding, get in touch.",
        cs: "INTEGRITA SOUBORŮ A MALWARE: {count} {unit}\n  \
             Kontrola {when} našla: {what}.\n  \
             Ne každý nález znamená útok — ručně upravený soubor vypadá stejně.\n  \
             Pokud si nějakým nálezem nejste jistí, ozvěte se.",
    },
    LetterString {
        id: "care.integrity.what_core",
        group: "Care report — file integrity",
        note: "One item in the findings list. Token: {count}.",
        en: "modified WordPress core files ({count})",
        cs: "změněné soubory jádra WordPressu ({count})",
    },
    LetterString {
        id: "care.integrity.what_plugin",
        group: "Care report — file integrity",
        note: "One item in the findings list. Token: {count}.",
        en: "modified plugin files ({count})",
        cs: "změněné soubory pluginů ({count})",
    },
    LetterString {
        id: "care.integrity.what_malware",
        group: "Care report — file integrity",
        note: "One item in the findings list. Token: {count}.",
        en: "suspicious code ({count})",
        cs: "podezřelý kód ({count})",
    },
    LetterString {
        id: "care.integrity.no_checksums",
        group: "Care report — file integrity",
        note: "Appended when the checksum half did not run — in every branch, because the customer is owed it.",
        en: "\n  We could not verify the file checksums, so that part is unknown.",
        cs: "\n  Kontrolní součty souborů se nám ověřit nepodařilo, tato část tedy\n  \
             zůstává neznámá.",
    },
    LetterString {
        id: "care.integrity.no_malware_scan",
        group: "Care report — file integrity",
        note: "Appended when the malware scanner was not running.",
        en: "\n  The malware scanner was not running on the server, so we say\n  \
             nothing about suspicious code.",
        cs: "\n  Skener malwaru na serveru neběžel, o podezřelém kódu tedy nic\n  \
             netvrdíme.",
    },
    // ── The disclosure a custom letter cannot delete ────────────────────
    //
    // Omitting a MEASURED section is the operator's editorial choice.
    // Omitting an UNMEASURED one removes a disclosure, so it is re-attached
    // here — in the operator's own language, which is the whole point.
    LetterString {
        id: "care.unmeasured.note",
        group: "Care report — frame",
        note: "Added automatically when a custom letter leaves out a section that would have said \"not measured\". Tokens: {list} {pronoun}.",
        en: "\n\nNOT MEASURED THIS PERIOD: {list}.\n  \
             We were not measuring {pronoun} during this period, so this letter makes\n  \
             no claim about {pronoun}. This note is added automatically — a report may\n  \
             leave a figure out, but never a gap in what was watched.",
        cs: "\n\nV TOMTO OBDOBÍ NEMĚŘENO: {list}.\n  \
             Tyto věci jsme v daném období neměřili, takže o nich tento dopis nic\n  \
             netvrdí. Tato poznámka se přidává automaticky — report může vynechat\n  \
             údaj, ale nikdy ne mezeru v tom, co bylo sledováno.",
    },
    LetterString {
        id: "care.unmeasured.pronoun",
        group: "Care report — frame",
        note: "Plural forms of \"it / them\" used by the note above, separated by |.",
        en: "it|them",
        cs: "to|je|je",
    },
    LetterString {
        id: "care.unmeasured.attacks",
        group: "Care report — frame",
        note: "Name of the attacks section in the \"not measured\" list.",
        en: "attacks blocked",
        cs: "zablokované útoky",
    },
    LetterString {
        id: "care.unmeasured.updates",
        group: "Care report — frame",
        note: "Name of the updates section in the \"not measured\" list.",
        en: "updates applied",
        cs: "provedené aktualizace",
    },
    LetterString {
        id: "care.unmeasured.traffic",
        group: "Care report — frame",
        note: "Name of the traffic section in the \"not measured\" list.",
        en: "traffic",
        cs: "návštěvnost",
    },
    LetterString {
        id: "care.unmeasured.uptime",
        group: "Care report — frame",
        note: "Name of the availability section in the \"not measured\" list.",
        en: "availability",
        cs: "dostupnost",
    },
    LetterString {
        id: "care.unmeasured.backups",
        group: "Care report — frame",
        note: "Name of the backups section in the \"not measured\" list.",
        en: "backups",
        cs: "zálohy",
    },
    LetterString {
        id: "care.unmeasured.integrity",
        group: "Care report — frame",
        note: "Name of the file-integrity section in the \"not measured\" list.",
        en: "file integrity and malware",
        cs: "integrita souborů a malware",
    },
    // ── Expiry warning ─────────────────────────────────────────────────
    LetterString {
        id: "expiry.subject.today",
        group: "Expiry warning",
        note: "Subject when the hosting expires today. Token: {domain}.",
        en: "[Hyperion] Hosting for {domain} expires today",
        cs: "[Hyperion] Hosting pro {domain} vyprší dnes",
    },
    LetterString {
        id: "expiry.subject.days",
        group: "Expiry warning",
        note: "Subject with days remaining. Tokens: {domain} {days} {unit}.",
        en: "[Hyperion] Hosting for {domain} expires in {days} {unit}",
        cs: "[Hyperion] Hosting pro {domain} vyprší za {days} {unit}",
    },
    LetterString {
        id: "expiry.when.today",
        group: "Expiry warning",
        note: "Fills {when} in the body when the hosting expires today.",
        en: "expires today",
        cs: "vyprší dnes",
    },
    LetterString {
        id: "expiry.when.days",
        group: "Expiry warning",
        note: "Fills {when} in the body. Tokens: {date} {days} {unit}.",
        en: "expires on {date} — {days} {unit} left",
        cs: "vyprší {date} — zbývá {days} {unit}",
    },
    LetterString {
        id: "expiry.body",
        group: "Expiry warning",
        note: "The whole letter. Tokens: {domain} {when} {expires_at} {grace_days} {delete_at}, plus {days_left} and the *_count / *_iso bare values.",
        en: "Hello,\n\
             \n\
             hosting for {domain} {when}.\n\
             \n\
             If it is not renewed before then:\n\
             - on {expires_at} the hosting will be suspended and visitors will see an information page instead of the site,\n\
             - after a grace period of {grace_days}, on {delete_at}, the hosting and its data will be deleted.\n\
             \n\
             To renew, please get in touch.\n\
             \n\
             --\n\
             Hyperion\n",
        cs: "Dobrý den,\n\
             \n\
             hosting pro {domain} {when}.\n\
             \n\
             Pokud nebude do té doby obnoven:\n\
             - {expires_at} bude hosting pozastaven a návštěvníkům se místo webu zobrazí informační stránka,\n\
             - po ochranné lhůtě {grace_days}, tedy {delete_at}, bude hosting i jeho data smazán.\n\
             \n\
             Pro obnovení nás prosím kontaktujte.\n\
             \n\
             --\n\
             Hyperion\n",
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    /// The failure this guards against reaches a paying customer: a string
    /// added in English only renders an English paragraph in the middle of
    /// a Czech letter, and nobody notices until the customer asks.
    #[test]
    fn every_string_is_translated() {
        for s in STRINGS {
            // Not `trim()`: a separator is allowed to BE whitespace — Czech
            // groups thousands with a space — and rejecting that would push
            // the one string the language actually needs out of the table.
            assert!(!s.en.is_empty(), "{} has no English text", s.id);
            assert!(!s.cs.is_empty(), "{} has no Czech text", s.id);
            if !s.id.ends_with("_sep") {
                assert!(!s.en.trim().is_empty(), "{} is blank in English", s.id);
                assert!(!s.cs.trim().is_empty(), "{} is blank in Czech", s.id);
            }
            assert!(!s.note.trim().is_empty(), "{} has no note", s.id);
            assert!(!s.group.trim().is_empty(), "{} has no group", s.id);
        }
    }

    #[test]
    fn ids_are_unique() {
        let mut seen: Vec<&str> = Vec::new();
        for s in STRINGS {
            assert!(!seen.contains(&s.id), "duplicate id {}", s.id);
            seen.push(s.id);
        }
    }

    /// A plural string must offer at least as many forms as its language
    /// has, or "5 dny" goes out to a customer.
    #[test]
    fn plural_strings_carry_enough_forms() {
        for s in STRINGS {
            if !s.id.starts_with("unit_") && !s.id.ends_with(".pronoun") {
                continue;
            }
            assert_eq!(
                s.en.split('|').count(),
                2,
                "{} needs two English forms",
                s.id
            );
            assert_eq!(
                s.cs.split('|').count(),
                3,
                "{} needs three Czech forms",
                s.id
            );
        }
    }

    #[test]
    fn czech_picks_the_right_plural_form() {
        let c = LetterCatalog::new(LetterLang::Cs);
        assert_eq!(c.plural("unit_day", 1), "den");
        assert_eq!(c.plural("unit_day", 2), "dny");
        assert_eq!(c.plural("unit_day", 4), "dny");
        assert_eq!(c.plural("unit_day", 5), "dní");
        assert_eq!(c.plural("unit_day", 0), "dní");
        assert_eq!(c.plural("unit_day", 30), "dní");
    }

    #[test]
    fn english_picks_the_right_plural_form() {
        let c = LetterCatalog::new(LetterLang::En);
        assert_eq!(c.plural("unit_day", 1), "day");
        assert_eq!(c.plural("unit_day", 0), "days");
        assert_eq!(c.plural("unit_day", 30), "days");
    }

    /// A two-form override on a three-form language must degrade to a real
    /// word, never to an empty one.
    #[test]
    fn missing_plural_form_falls_back_to_the_last() {
        let mut c = LetterCatalog::new(LetterLang::Cs);
        c.overrides.insert("unit_day".into(), "den|dnů".into());
        assert_eq!(c.plural("unit_day", 1), "den");
        assert_eq!(c.plural("unit_day", 2), "dnů");
        assert_eq!(c.plural("unit_day", 9), "dnů");
    }

    #[test]
    fn overrides_win_but_blank_ones_do_not() {
        let mut c = LetterCatalog::new(LetterLang::Cs);
        c.overrides
            .insert("care.unmeasured.traffic".into(), "provoz".into());
        c.overrides
            .insert("care.unmeasured.backups".into(), "   ".into());
        assert_eq!(c.get("care.unmeasured.traffic"), "provoz");
        // Blank means "no override" — clearing the field in Settings is how
        // an operator goes back to the built-in wording.
        assert_eq!(c.get("care.unmeasured.backups"), "zálohy");
    }

    #[test]
    fn numbers_follow_the_language() {
        let en = LetterCatalog::new(LetterLang::En);
        let cs = LetterCatalog::new(LetterLang::Cs);
        assert_eq!(en.group_int(1_234_567), "1,234,567");
        assert_eq!(cs.group_int(1_234_567), "1 234 567");
        assert_eq!(en.group_int(-1_000), "-1,000");
        assert_eq!(en.decimal("34.5 MB"), "34.5 MB");
        assert_eq!(cs.decimal("34.5 MB"), "34,5 MB");
        // Only the FIRST full stop moves: "1.5 GB. Next sentence." must not
        // lose its sentence break.
        assert_eq!(cs.decimal("1.5 GB. x"), "1,5 GB. x");
    }

    #[test]
    fn months_fall_back_when_an_override_is_short() {
        let mut c = LetterCatalog::new(LetterLang::Cs);
        c.overrides
            .insert("date_months".into(), "leden,únor".into());
        assert_eq!(c.months().len(), 12);
        assert_eq!(c.months()[0], "led");
    }

    #[test]
    fn unknown_id_stays_visible() {
        let c = LetterCatalog::new(LetterLang::En);
        assert_eq!(c.get("care.no.such.string"), "care.no.such.string");
    }

    #[test]
    fn unknown_token_is_left_literal() {
        assert_eq!(render_template("a {x} b", &[("y", "1")]), "a {x} b");
        assert_eq!(render_template("a {x} b", &[("x", "1")]), "a 1 b");
        // A value carrying a brace is not re-scanned.
        assert_eq!(render_template("{x}", &[("x", "{x}")]), "{x}");
    }

    #[test]
    fn effective_overrides_drop_blanks_and_strangers() {
        let mut c = LetterCatalog::new(LetterLang::Cs);
        c.overrides.insert("unit_day".into(), "den|dny|dní".into());
        c.overrides.insert("unit_check".into(), "  ".into());
        c.overrides.insert("not_a_string".into(), "x".into());
        let eff = c.effective_overrides();
        assert_eq!(eff.len(), 1);
        assert!(eff.contains_key("unit_day"));
    }

    #[test]
    fn lang_parse_is_forgiving_and_defaults_to_english() {
        assert_eq!(LetterLang::parse("cs"), LetterLang::Cs);
        assert_eq!(LetterLang::parse(" CZ "), LetterLang::Cs);
        assert_eq!(LetterLang::parse("klingon"), LetterLang::En);
        assert_eq!(LetterLang::parse(""), LetterLang::En);
    }
}
