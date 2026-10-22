//! Tests for `service::billing`.

use super::*;

/// The spolchemie.cz announcement: a 2 150 CZK/year hosting with a
/// 1 500 CZK/month plan printed "2150,00 CZK (yearly)" as THE price,
/// "1500.00" in the other format, raw English cycles, and no total.
#[test]
fn billing_prices_read_like_an_invoice() {
    use super::{billing_total, fmt_billing_price};
    let cs = LetterCatalog::new(LetterLang::Cs);
    let en = LetterCatalog::new(LetterLang::En);
    assert_eq!(
        fmt_billing_price(&cs, 150_000, "CZK", "monthly"),
        "1 500,00 CZK měsíčně"
    );
    assert_eq!(
        fmt_billing_price(&en, 215_000, "CZK", "yearly"),
        "2,150.00 CZK per year"
    );
    assert_eq!(
        fmt_billing_price(&cs, 5, "EUR", "quarterly"),
        "0,05 EUR čtvrtletně"
    );
    assert_eq!(
        fmt_billing_price(&cs, 100, "CZK", "weekly"),
        "1,00 CZK weekly"
    );

    // Mixed cycles add up per year: 2 150 + 12 × 1 500.
    assert_eq!(
        billing_total(&[(215_000, "CZK", "yearly"), (150_000, "CZK", "monthly")]),
        Some((2_015_000, "CZK".into(), "yearly".into()))
    );
    // One cycle stays on that cycle.
    assert_eq!(
        billing_total(&[(10_000, "CZK", "monthly"), (150_000, "CZK", "monthly")]),
        Some((160_000, "CZK".into(), "monthly".into()))
    );
    assert_eq!(
        billing_total(&[(1, "CZK", "monthly"), (1, "EUR", "monthly")]),
        None
    );
    assert_eq!(
        billing_total(&[(1, "CZK", "monthly"), (1, "CZK", "weekly")]),
        None
    );
    assert_eq!(billing_total(&[]), None);
}

/// The reminder goes out a lead window before the billing date, or on
/// the next pass when that moment has already gone.
#[test]
fn billing_reminder_lands_before_the_due_date() {
    use super::{billing_reminder_at, BILLING_REMINDER_LEAD_SECS};
    let now = 1_000_000;
    let due = now + 30 * 86_400;
    assert_eq!(
        billing_reminder_at(due, now),
        due - BILLING_REMINDER_LEAD_SECS
    );
    assert_eq!(billing_reminder_at(now + 86_400, now), now);
}

#[test]
fn advance_billing_date_steps_strictly_past_now() {
    use super::advance_billing_date;
    let day = 86400;
    // Just due now → advance exactly one interval past it.
    assert_eq!(
        advance_billing_date(1_000, "monthly", 1_000),
        Some(1_000 + 30 * day)
    );
    // Dormant agent (100 days late) → catch up to the FIRST future boundary,
    // not one step (which would still be in the past) and not 100 reminders.
    let now = 1_000 + 100 * day;
    let next = advance_billing_date(1_000, "monthly", now).expect("monthly");
    assert!(next > now, "must land strictly after now");
    assert_eq!((next - 1_000) % (30 * day), 0, "on an interval boundary");
    assert!(
        next - now <= 30 * day,
        "first future boundary, no overshoot"
    );
    // Unknown interval → no recurrence.
    assert_eq!(advance_billing_date(1_000, "weekly", 1_000), None);
}

#[tokio::test]
async fn a_hosting_price_needs_all_three_parts_or_none() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), happy_mocks());
    s.create(req("cena.cz")).await.expect("create");
    let sel = HostingSelector::Domain(Domain::parse("cena.cz").unwrap());
    for (cur, iv) in [
        (None, Some("yearly")),
        (Some("CZK"), None),
        (Some("KČ"), Some("yearly")),
        (Some("CZK"), Some("weekly")),
    ] {
        let err = s
            .hosting_price_set(
                sel.clone(),
                Some(100),
                cur.map(Into::into),
                iv.map(Into::into),
                false,
            )
            .await
            .expect_err("refused");
        assert!(
            matches!(err, RpcError::Validation { .. }),
            "{cur:?} {iv:?}: {err:?}"
        );
    }
    assert!(matches!(
        s.hosting_price_set(
            sel.clone(),
            Some(-1),
            Some("CZK".into()),
            Some("yearly".into()),
            false
        )
        .await,
        Err(RpcError::Validation { .. })
    ));
    // No amount drops the price, whatever else came along with it.
    let cleared = s
        .hosting_price_set(sel, None, Some("CZK".into()), Some("yearly".into()), true)
        .await
        .expect("clear");
    assert_eq!(cleared.price_minor, None);
    assert_eq!(cleared.price_interval, None);
    assert_eq!(cleared.next_billing_at, None, "no price, no billing clock");
    assert!(cleared.price_pinned);
}
