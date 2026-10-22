//! Hosting prices and the billing sweep that sends renewal reminders.

use super::*;

impl<A: AdapterPort + 'static> HostingService<A> {
    /// What this hosting costs, in words: the plan price from the profile, the
    /// care packages on top, and a combined total.
    ///
    /// Shared by the new-hosting announcement and the care-plan one so the two
    /// can never disagree about the same site. Prices come from the SNAPSHOTS
    /// taken at apply/activation time, not from the live definitions — a later
    /// re-price must not rewrite what the customer agreed to.
    ///
    /// Currencies are summed only when they all match. Mixing CZK and EUR into
    /// one number would be a wrong figure quoted with confidence, so the parts
    /// are listed and the total is left out.
    pub(super) async fn price_picture(&self, id: &HostingId) -> (String, String, String) {
        let applied = hyperion_state::profiles::get_apply(&self.pool, id)
            .await
            .ok()
            .flatten();
        let base = applied.as_ref().and_then(|a| {
            match (a.price_minor, &a.price_currency, &a.price_interval) {
                (Some(m), Some(c), Some(iv)) => Some((m, c.clone(), iv.clone())),
                _ => None,
            }
        });

        let packages = hyperion_state::packages::list_for_hosting(&self.pool, id)
            .await
            .unwrap_or_default();
        let cat = self.letter_catalog();
        let plan_line = if packages.is_empty() {
            cat.get("slack.plan_none").to_string()
        } else {
            let names: Vec<String> = packages
                .iter()
                .map(
                    |p| match (p.price_minor, &p.price_currency, &p.price_interval) {
                        (Some(m), Some(c), Some(iv)) => {
                            format!("{} — {}", p.package_name, fmt_billing_price(&cat, m, c, iv))
                        }
                        _ => p.package_name.clone(),
                    },
                )
                .collect();
            cat.render("slack.plan_some", &[("names", &names.join(", "))])
        };

        let base_line = match &base {
            Some((m, c, iv)) => cat.render(
                "slack.price_line",
                &[("price", &fmt_billing_price(&cat, *m, c, iv))],
            ),
            None => cat.get("slack.price_unset").to_string(),
        };

        // Every part priced, or no total: a package with no price cannot be
        // added up, and saying nothing beats a total that quietly omits it.
        let mut parts: Vec<(i64, &str, &str)> = Vec::new();
        if let Some((m, c, iv)) = &base {
            parts.push((*m, c.as_str(), iv.as_str()));
        }
        let mut all_priced = true;
        for p in &packages {
            match (p.price_minor, &p.price_currency, &p.price_interval) {
                (Some(m), Some(c), Some(iv)) => parts.push((m, c.as_str(), iv.as_str())),
                _ => all_priced = false,
            }
        }
        let total_line = match billing_total(&parts) {
            Some((sum, c, iv)) if all_priced && !packages.is_empty() => cat.render(
                "slack.total",
                &[("total", &fmt_billing_price(&cat, sum, &c, &iv))],
            ),
            _ => String::new(),
        };
        (base_line, plan_line, total_line)
    }

    /// The "next invoice" line for one billing clock: the date the period
    /// starts and the moment the sweep will really send its reminder (a lead
    /// window earlier). Printing the billing date as "next reminder" promised
    /// a message three days after it would actually arrive.
    pub(super) fn next_invoice_line(
        cat: &LetterCatalog,
        what: &str,
        due: Option<i64>,
        now: i64,
    ) -> String {
        match due {
            Some(t) => cat.render(
                "slack.next_reminder",
                &[
                    ("what", what),
                    ("due", &fmt_notif_time(t)),
                    ("when", &fmt_notif_time(billing_reminder_at(t, now))),
                ],
            ),
            None => cat.get("slack.next_reminder_none").to_string(),
        }
    }

    /// Periodic sweep — sends one Slack + email reminder per hosting whose
    /// `next_billing_at` falls within the next 3 days, then ADVANCES the date by
    /// one billing interval so the reminder fires once per cycle instead of
    /// re-firing every tick forever. Called hourly from the agent scheduler.
    ///
    /// Two sources, same treatment: the hosting's applied profile, and each
    /// care package it holds. They are separate rows on separate clocks
    /// (a hosting carries one profile but may hold several packages), so a
    /// site can legitimately produce more than one reminder. Neither
    /// charges anyone — this only ever sends a message.
    pub async fn billing_sweep(&self) -> Result<i64, RpcError> {
        let now = now_secs();
        let due = profiles::due_billings(&self.pool, now, BILLING_REMINDER_LEAD_SECS)
            .await
            .map_err(|e| RpcError::Internal_with(format!("billing sweep: {e}")))?;
        let mut count = 0i64;
        for row in due {
            // Look up hosting + profile (for webhook + label) — best effort.
            let detail = self
                .get(HostingSelector::Id(row.hosting_id.clone()))
                .await
                .ok();
            let domain = detail
                .as_ref()
                .map(|d| d.domain.clone())
                .unwrap_or_default();
            // Prefer the webhook snapshotted at apply (survives a profile
            // delete); fall back to the live profile lookup for old rows whose
            // snapshot is null.
            let webhook = match row.slack_webhook.clone() {
                Some(w) => Some(w),
                None => match row.profile_id {
                    Some(pid) => self
                        .profile_get(pid)
                        .await
                        .ok()
                        .and_then(|p| p.slack_webhook),
                    None => None,
                },
            };
            let due_in_days = row
                .next_billing_at
                .map(|t| ((t - now).max(0)) / 86400)
                .unwrap_or(0);
            let cat = self.billing_catalog();
            let (price_str, action) =
                match (row.price_minor, &row.price_currency, &row.price_interval) {
                    (Some(m), Some(c), Some(iv)) => (
                        fmt_billing_price(&cat, m, c, iv),
                        cat.render(
                            "slack.invoice_action",
                            &[
                                ("amount", &fmt_billing_amount(&cat, m, c)),
                                ("interval", &fmt_billing_interval(&cat, iv)),
                            ],
                        ),
                    ),
                    _ => (
                        cat.get("slack.price_not_set").to_string(),
                        cat.get("slack.no_price_hosting").to_string(),
                    ),
                };
            let msg = cat.render(
                "slack.hosting_due",
                &[
                    ("domain", &domain),
                    ("price", &price_str),
                    ("days", &due_in_days.to_string()),
                    ("action", &action),
                ],
            );
            self.notify_slack(webhook.as_deref(), &msg).await;
            // Also send email if configured. Use the hosting's
            // owner_email when set (from expiry config), else the
            // cluster-wide email_default_to.
            let owner = self
                .get_expiry(HostingSelector::Id(row.hosting_id.clone()))
                .await
                .ok()
                .and_then(|e| e.owner_email);
            let to = owner.unwrap_or_default();
            let subj = cat.render("billing.email_subject", &[("domain", &domain)]);
            let body = cat.render(
                "billing.email_body",
                &[
                    ("domain", &domain),
                    ("price", &price_str),
                    ("days", &due_in_days.to_string()),
                ],
            );
            self.notify_email(&to, &subj, &body, Some(row.hosting_id.as_str()), "billing")
                .await;
            // Advance the billing clock past `now` so this reminder fires once
            // per cycle instead of re-firing every tick forever. A row with no
            // interval can't recur, so clear its date to stop it being due.
            let advanced = row
                .price_interval
                .as_deref()
                .and_then(|iv| advance_billing_date(row.next_billing_at.unwrap_or(now), iv, now));
            if let Err(e) = profiles::set_next_billing(&self.pool, &row.hosting_id, advanced).await
            {
                tracing::warn!(
                    hosting_id = %row.hosting_id.as_str(),
                    error = %e,
                    "billing: failed to advance next_billing_at; reminder may repeat"
                );
            }
            count += 1;
        }

        // Care packages, on exactly the same terms. `packages::due_billings`
        // mirrors the profile query (active only, non-trashed, clock inside
        // the window), so everything below is the profile branch with a
        // package label — including advancing the clock, without which the
        // same package re-notifies every hour forever.
        let due_packages = packages::due_billings(&self.pool, now, BILLING_REMINDER_LEAD_SECS)
            .await
            .map_err(|e| RpcError::Internal_with(format!("billing sweep (packages): {e}")))?;
        for row in due_packages {
            let detail = self
                .get(HostingSelector::Id(row.hosting_id.clone()))
                .await
                .ok();
            let domain = detail
                .as_ref()
                .map(|d| d.domain.clone())
                .unwrap_or_default();
            // From the activation's OWN snapshot, not the definition: a
            // retired or renamed package must still name itself correctly in
            // the reminder the customer's invoice is matched against.
            let name = row.package_name.clone();
            let label = if name.is_empty() {
                "care package (definition deleted)".to_string()
            } else {
                name
            };
            // Packages carry no webhook of their own; reuse the one the
            // hosting's profile apply snapshotted so a site's money-related
            // messages land in one channel. `None` ⇒ the cluster default.
            let webhook = profiles::get_apply(&self.pool, &row.hosting_id)
                .await
                .ok()
                .flatten()
                .and_then(|a| a.slack_webhook);
            let due_in_days = row
                .next_billing_at
                .map(|t| ((t - now).max(0)) / 86400)
                .unwrap_or(0);
            // Name the ACTION, not just the date. A reminder that says only
            // "due in 2 days" is a fact; the operator still has to work out
            // that it means "raise an invoice for this amount". A recurring
            // care fee that nobody invoices is revenue quietly lost every
            // month, which is exactly what this message exists to prevent.
            let cat = self.billing_catalog();
            let (price_str, action) =
                match (row.price_minor, &row.price_currency, &row.price_interval) {
                    (Some(m), Some(c), Some(iv)) => (
                        fmt_billing_price(&cat, m, c, iv),
                        cat.render(
                            "slack.invoice_action",
                            &[
                                ("amount", &fmt_billing_amount(&cat, m, c)),
                                ("interval", &fmt_billing_interval(&cat, iv)),
                            ],
                        ),
                    ),
                    // Said out loud rather than skipped: a care package with
                    // no price is one nobody is charging for, and the day it
                    // comes due is when that is worth noticing.
                    _ => (
                        cat.get("slack.price_not_set").to_string(),
                        cat.get("slack.no_price_package").to_string(),
                    ),
                };
            let msg = cat.render(
                "slack.package_due",
                &[
                    ("domain", &domain),
                    ("package", &label),
                    ("price", &price_str),
                    ("days", &due_in_days.to_string()),
                    ("action", &action),
                ],
            );
            self.notify_slack(webhook.as_deref(), &msg).await;
            let owner = self
                .get_expiry(HostingSelector::Id(row.hosting_id.clone()))
                .await
                .ok()
                .and_then(|e| e.owner_email);
            let to = owner.unwrap_or_default();
            let subj = cat.render("billing.email_subject", &[("domain", &domain)]);
            let body = cat.render(
                "billing.email_body_package",
                &[
                    ("domain", &domain),
                    ("package", &label),
                    ("price", &price_str),
                    ("days", &due_in_days.to_string()),
                ],
            );
            self.notify_email(&to, &subj, &body, Some(row.hosting_id.as_str()), "billing")
                .await;
            let advanced = row
                .price_interval
                .as_deref()
                .and_then(|iv| advance_billing_date(row.next_billing_at.unwrap_or(now), iv, now));
            if let Err(e) = packages::set_next_billing(&self.pool, row.id, advanced).await {
                tracing::warn!(
                    hosting_id = %row.hosting_id.as_str(),
                    activation_id = row.id,
                    error = %e,
                    "billing: failed to advance a package's next_billing_at; reminder may repeat"
                );
            }
            count += 1;
        }
        Ok(count)
    }

    /// Set one hosting's price by hand (Lifecycle & billing card). An amount
    /// needs a currency and an interval; no amount drops the price entirely.
    /// The billing clock follows the same rule as a profile apply. `pinned`
    /// decides whether the next profile apply keeps this price.
    pub async fn hosting_price_set(
        &self,
        sel: HostingSelector,
        price_minor: Option<i64>,
        price_currency: Option<String>,
        price_interval: Option<String>,
        pinned: bool,
    ) -> Result<ProfileApply, RpcError> {
        let (price_minor, price_currency, price_interval) =
            validate_hosting_price(price_minor, price_currency, price_interval)?;
        let detail = self.get(sel).await?;
        let now = now_secs();
        let existing = profiles::get_apply(&self.pool, &detail.id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("apply read: {e}")))?;
        let next = next_billing_on_price_change(existing.as_ref(), price_interval.as_deref(), now);
        profiles::set_price(
            &self.pool,
            &detail.id,
            price_minor,
            price_currency.as_deref(),
            price_interval.as_deref(),
            next,
            pinned,
            now,
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("price set: {e}")))?;
        self.append_audit(
            "hosting.price.set",
            Some(detail.id.as_str()),
            &serde_json::json!({
                "old": existing.as_ref().map(|e| serde_json::json!({
                    "price_minor": e.price_minor,
                    "price_currency": e.price_currency,
                    "price_interval": e.price_interval,
                    "pinned": e.price_pinned,
                })),
                "price_minor": price_minor,
                "price_currency": price_currency,
                "price_interval": price_interval,
                "pinned": pinned,
            })
            .to_string(),
            "ok",
        )
        .await;
        self.profile_get_apply(HostingSelector::Id(detail.id))
            .await?
            .ok_or_else(|| RpcError::Internal_with("price set: row vanished".into()))
    }
}

/// How long before a billing date its reminder goes out. The sweep picks a
/// clock up once it is inside this window, so "the next reminder" a message
/// promises is this much earlier than the billing date itself.
pub(super) const BILLING_REMINDER_LEAD_SECS: i64 = 3 * 86400;

/// When the billing sweep will actually send the reminder for a clock due at
/// `due`: one lead window earlier, but never in the past — a clock already
/// inside the window goes out on the next hourly pass.
pub(super) fn billing_reminder_at(due: i64, now: i64) -> i64 {
    (due - BILLING_REMINDER_LEAD_SECS).max(now)
}

/// Billing periods in a year, counted the way an invoice counts them (twelve
/// months, four quarters) rather than by the 30/90/365-day clock step.
pub(super) fn billing_periods_per_year(interval: &str) -> Option<i64> {
    match interval {
        "monthly" => Some(12),
        "quarterly" => Some(4),
        "yearly" => Some(1),
        _ => None,
    }
}

/// A price as an operator reads it on an invoice: "1 500,00 CZK měsíčně" in
/// Czech, "1,500.00 CZK per month" in English. Grouped and separated by the
/// letter language, and the cycle in words — the raw "monthly" token in a
/// Czech message is the stored enum leaking out, not a sentence.
pub(super) fn fmt_billing_price(
    cat: &LetterCatalog,
    minor: i64,
    currency: &str,
    interval: &str,
) -> String {
    format!(
        "{} {}",
        fmt_billing_amount(cat, minor, currency),
        fmt_billing_interval(cat, interval)
    )
}

/// The amount alone, "1 500,00 CZK".
pub(super) fn fmt_billing_amount(cat: &LetterCatalog, minor: i64, currency: &str) -> String {
    let sign = if minor < 0 { "-" } else { "" };
    let abs = minor.unsigned_abs();
    format!(
        "{sign}{}{}{:02} {currency}",
        cat.group_int((abs / 100) as i64),
        cat.get("num_decimal_sep"),
        abs % 100
    )
}

/// The cycle in words, "per month" / "měsíčně"; an interval the catalogue does
/// not know is shown as stored rather than hidden.
pub(super) fn fmt_billing_interval(cat: &LetterCatalog, interval: &str) -> String {
    match interval {
        "monthly" | "quarterly" | "yearly" => cat.get(&format!("price.per.{interval}")).to_string(),
        other => other.to_string(),
    }
}

/// Add up a hosting's prices: `(minor, currency, interval)` per part.
///
/// One cycle throughout sums on that cycle. Mixed cycles — a yearly hosting
/// with a monthly care plan, the common case — sum per YEAR, because that
/// is a figure that is actually true; refusing to add them left the operator
/// with no total at all on exactly the sites that have a plan. Mixed
/// currencies, or a cycle with no yearly equivalent, give `None`.
pub(super) fn billing_total(parts: &[(i64, &str, &str)]) -> Option<(i64, String, String)> {
    let (_, currency, first_iv) = *parts.first()?;
    if parts.iter().any(|(_, c, _)| *c != currency) {
        return None;
    }
    if parts.iter().all(|(_, _, iv)| *iv == first_iv) {
        let sum = parts.iter().map(|(m, _, _)| *m).sum();
        return Some((sum, currency.to_string(), first_iv.to_string()));
    }
    let mut sum = 0i64;
    for (m, _, iv) in parts {
        sum += m.checked_mul(billing_periods_per_year(iv)?)?;
    }
    Some((sum, currency.to_string(), "yearly".to_string()))
}

/// Seconds in one billing interval, or `None` for an unknown/absent interval.
pub(super) fn billing_interval_secs(interval: &str) -> Option<i64> {
    match interval {
        "monthly" => Some(30 * 86400),
        "quarterly" => Some(90 * 86400),
        "yearly" => Some(365 * 86400),
        _ => None,
    }
}

/// Next billing date strictly after `now`, stepping `current` forward by whole
/// intervals (so a long-dormant agent catches up without re-firing a reminder
/// for every period it slept through). `None` for an unknown interval.
pub(super) fn advance_billing_date(current: i64, interval: &str, now: i64) -> Option<i64> {
    let step = billing_interval_secs(interval)?;
    let mut next = current + step;
    while next <= now {
        next += step;
    }
    Some(next)
}

/// The billing clock after a site's price is (re)set, by a profile apply or by
/// hand. A first price, or a new interval, starts a fresh clock at now +
/// interval. The same interval KEEPS the running date — re-applying a profile
/// to push a limit change, or correcting the amount, must not shove the
/// billing date forward and skip an imminent reminder. No interval, no clock.
pub(super) fn next_billing_on_price_change(
    existing: Option<&profiles::ProfileApplyRow>,
    interval: Option<&str>,
    now: i64,
) -> Option<i64> {
    match existing {
        Some(e) if e.price_interval.as_deref() == interval && e.next_billing_at.is_some() => {
            e.next_billing_at
        }
        _ => interval.and_then(billing_interval_secs).map(|s| now + s),
    }
}

/// A hand-set hosting price: all three parts, or none. Currency is trimmed and
/// upper-cased (the field only LOOKS uppercase); blanks count as missing.
pub(super) fn validate_hosting_price(
    price_minor: Option<i64>,
    price_currency: Option<String>,
    price_interval: Option<String>,
) -> Result<(Option<i64>, Option<String>, Option<String>), RpcError> {
    let Some(minor) = price_minor else {
        return Ok((None, None, None));
    };
    let invalid = |m: &str| RpcError::Validation { message: m.into() };
    if minor < 0 {
        return Err(invalid("price must not be negative"));
    }
    let currency = price_currency
        .map(|c| c.trim().to_ascii_uppercase())
        .filter(|c| !c.is_empty())
        .ok_or_else(|| invalid("a price needs a currency"))?;
    if currency.len() != 3 || !currency.chars().all(|ch| ch.is_ascii_uppercase()) {
        return Err(invalid("currency must be 3 ISO-4217 letters, e.g. CZK"));
    }
    let interval = price_interval
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| invalid("a price needs a billing interval"))?;
    if billing_interval_secs(&interval).is_none() {
        return Err(invalid("interval must be monthly | quarterly | yearly"));
    }
    Ok((Some(minor), Some(currency), Some(interval)))
}
