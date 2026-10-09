//! /protection — is the WAF working, and is it working against the right
//! people? (Replaces the old /bans page, which listed only live bans and so
//! sat empty most of the time.)
//!
//! Fans `WafOverview { days: 7 }` out across the master + every enrolled
//! node: each answers from its own hit records and ban table (all of it is
//! node-local), and [`build`] folds the answers into one cluster view.
//! A node too old to know the request still contributes its active bans
//! through `BanList`, so the page never shows less than /bans used to.
//!
//! Every field of a refusal but its time and address is attacker-controlled
//! — askama escapes it, and nothing here interprets it.

use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::state::SharedState;
use askama::Template;
use axum::extract::State;
use axum::response::{Html, IntoResponse, Redirect, Response};
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use hyperion_state::capabilities::Capability;
use hyperion_types::waf::{self, WafOverview};
use hyperion_types::IpBanWire;
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap};

/// How far back the page looks.
pub const DAYS: u32 = 7;
/// A (site, rule) needs this many sampled refusals before its browser share
/// means anything.
const SUSPECT_MIN_SAMPLE: i64 = 5;
/// Rows in the tuning list.
const TUNING_ROWS: usize = 30;
/// Rows in the addresses list.
const IP_ROWS: usize = 20;
/// Sampled refusals an address needs to make that list (a banned one is
/// always listed): one visitor tripping a rule twice is not "busy".
const IP_MIN_HITS: i64 = 5;
/// Rows in the ban history.
const HISTORY_ROWS: usize = 100;

/// One node's contribution.
pub struct NodeData {
    pub node_id: String,
    pub label: String,
    pub data: NodeAnswer,
}

pub enum NodeAnswer {
    Overview(WafOverview),
    /// Too old for `WafOverview`; its active bans only.
    BansOnly(Vec<IpBanWire>),
}

/// One bar of the refusals chart: one UTC hour.
pub struct Bar {
    /// SVG x of the bar's left edge, in viewBox units.
    pub x: String,
    pub w: String,
    /// Heights / tops of the two stacked parts (ban-counted at the bottom).
    pub ban_y: String,
    pub ban_h: String,
    pub other_y: String,
    pub other_h: String,
    pub title: String,
}

pub struct Chart {
    pub bars: Vec<Bar>,
    pub peak: i64,
    pub has_data: bool,
    /// Day labels under the chart, `(x %, label)`.
    pub days: Vec<(String, String)>,
}

pub struct RuleRow {
    pub rule: String,
    pub label: &'static str,
    pub day: i64,
    pub week: i64,
    pub bans: bool,
}

pub struct TuneRow {
    pub node_id: String,
    pub hosting_id: String,
    pub domain: String,
    pub rule: String,
    pub label: &'static str,
    pub week: i64,
    pub sample: i64,
    /// Share of the sample sent by a real browser, 0–100.
    pub browser_pct: i64,
    pub ips: i64,
    pub last_ago: String,
    /// `METHOD uri` of the newest sampled refusal.
    pub request: String,
    /// Mostly real browsers: likely a false positive.
    pub suspect: bool,
    /// A catalogue rule, so it can be pinned off (geo / bot tags are
    /// choices the operator made on purpose, not rules to tune).
    pub pinnable: bool,
    /// The rule no longer applies on this site (turned off since these
    /// refusals were recorded).
    pub now_off: bool,
}

pub struct IpRow {
    pub ip: String,
    pub hits: i64,
    pub browser: bool,
    pub sites: String,
    pub rules: String,
    pub last_ago: String,
    /// "banned until …" / "banned permanently" when an active ban exists.
    pub ban: Option<String>,
}

pub struct BanRow {
    pub node_id: String,
    pub node_label: String,
    pub ip: String,
    pub kind: &'static str,
    pub reason: String,
    pub site: Option<(String, String)>,
    pub banned_ago: String,
    pub expires: String,
    /// History only: how it ended.
    pub ended: String,
}

pub struct SiteLink {
    pub hosting_id: String,
    pub domain: String,
    pub node_label: String,
}

/// Everything the template shows, built without I/O so it can be tested.
pub struct Page {
    pub verdict_tone: &'static str,
    pub verdict: String,
    pub blocked_24h: i64,
    pub blocked_7d: i64,
    pub banned_now: usize,
    pub bans_7d: usize,
    pub bans_7d_by_kind: String,
    pub sites_total: usize,
    pub sites_on: usize,
    pub sites_strict: usize,
    pub chart: Chart,
    pub rules: Vec<RuleRow>,
    pub tuning: Vec<TuneRow>,
    pub suspects: usize,
    pub ips: Vec<IpRow>,
    pub active_bans: Vec<BanRow>,
    pub history: Vec<BanRow>,
    pub unprotected: Vec<SiteLink>,
    /// Nodes with automatic banning switched off.
    pub fail2ban_off: Vec<String>,
    /// Nodes that answered with active bans only.
    pub old_nodes: Vec<String>,
}

/// What a ban was for, from its source + the scanner's fixed reasons.
pub fn ban_kind(source: &str, reason: &str) -> &'static str {
    if source == "manual" {
        return "Manual";
    }
    let r = reason.to_ascii_lowercase();
    if r.contains("waf") {
        "WAF"
    } else if r.contains("wp-login") || r.contains("xmlrpc") {
        "Login flood"
    } else if r.contains("ssh") {
        "SSH"
    } else if r.contains("ftp") {
        "FTP"
    } else if r.contains("mail") {
        "Mail"
    } else {
        "Automatic"
    }
}

fn ended_label(b: &IpBanWire) -> String {
    // Still flagged active but past its time: the node's sweep simply has
    // not run since.
    if b.active {
        return "ran out".into();
    }
    match b.end_reason.as_deref() {
        Some("expired") => "ran out".into(),
        Some("lifted") => match b.ended_at {
            Some(t) => format!("lifted {}", super::stats::fmt_ago(&t)),
            None => "lifted".into(),
        },
        Some("replaced") => "replaced by a newer ban".into(),
        // Ended before migration 080 recorded how.
        _ => "ended".into(),
    }
}

fn expires_label(b: &IpBanWire) -> String {
    if b.expires_at == 0 {
        "permanent".into()
    } else {
        super::stats::fmt_future(&b.expires_at)
    }
}

fn hour_label(ts: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(ts, 0)
        .map(|d| d.format("%a %d. %H:00 UTC").to_string())
        .unwrap_or_default()
}

fn day_label(ts: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(ts, 0)
        .map(|d| d.format("%a %d.").to_string())
        .unwrap_or_default()
}

/// Stacked hourly bars over the last `DAYS` days, ending with the current
/// hour: ban-counted refusals at the bottom, the rest on top.
fn build_chart(hourly: &BTreeMap<i64, (i64, i64)>, now: i64) -> Chart {
    const W: f64 = 600.0;
    const H: f64 = 80.0;
    let hours = DAYS as i64 * 24;
    let last = now - now.rem_euclid(3600);
    let first = last - (hours - 1) * 3600;
    let peak = hourly
        .range(first..=last)
        .map(|(_, (b, o))| b + o)
        .max()
        .unwrap_or(0);
    let slot = W / hours as f64;
    let w = (slot - 0.6).max(0.4);
    let scale = if peak > 0 { H / peak as f64 } else { 0.0 };
    let mut bars = Vec::new();
    for i in 0..hours {
        let hour = first + i * 3600;
        let Some(&(ban, other)) = hourly.get(&hour) else {
            continue;
        };
        if ban + other == 0 {
            continue;
        }
        let ban_h = ban as f64 * scale;
        let other_h = other as f64 * scale;
        bars.push(Bar {
            x: format!("{:.2}", i as f64 * slot),
            w: format!("{w:.2}"),
            ban_y: format!("{:.2}", H - ban_h),
            ban_h: format!("{ban_h:.2}"),
            other_y: format!("{:.2}", H - ban_h - other_h),
            other_h: format!("{other_h:.2}"),
            title: format!(
                "{} — {} refused, {} of them toward a ban",
                hour_label(hour),
                ban + other,
                ban
            ),
        });
    }
    // A label at each UTC midnight inside the window.
    let mut days = Vec::new();
    let mut d = first - first.rem_euclid(86_400) + 86_400;
    while d <= last {
        let pct = (d - first) as f64 / (hours * 3600) as f64 * 100.0;
        days.push((format!("{pct:.2}"), day_label(d)));
        d += 86_400;
    }
    Chart {
        has_data: !bars.is_empty(),
        bars,
        peak,
        days,
    }
}

/// Fold every node's answer into the page.
pub fn build(nodes: &[NodeData], now: i64) -> Page {
    let since_7d = now - DAYS as i64 * 86_400;
    // hosting id → (domain, node id, node label)
    let mut sites: HashMap<String, (String, String, String)> = HashMap::new();
    // hosting id → (rules in force, their ids)
    let mut active_rules: HashMap<String, (u32, Vec<String>)> = HashMap::new();
    let mut rule_tot: BTreeMap<String, (i64, i64)> = BTreeMap::new();
    let mut hourly: BTreeMap<i64, (i64, i64)> = BTreeMap::new();
    let mut blocked_24h = 0;
    let mut blocked_7d = 0;
    let (mut sites_total, mut sites_on, mut sites_strict) = (0, 0, 0);
    let mut unprotected = Vec::new();
    let mut fail2ban_off = Vec::new();
    let mut old_nodes = Vec::new();
    let mut week_by_site_rule: HashMap<(String, String), i64> = HashMap::new();
    let mut all_bans: Vec<(&NodeData, &IpBanWire)> = Vec::new();

    for n in nodes {
        let o = match &n.data {
            NodeAnswer::Overview(o) => o,
            NodeAnswer::BansOnly(b) => {
                old_nodes.push(n.label.clone());
                all_bans.extend(b.iter().map(|b| (n, b)));
                continue;
            }
        };
        if !o.fail2ban_enabled {
            fail2ban_off.push(n.label.clone());
        }
        for s in &o.sites {
            sites.insert(
                s.hosting_id.clone(),
                (s.domain.clone(), n.node_id.clone(), n.label.clone()),
            );
            sites_total += 1;
            active_rules.insert(s.hosting_id.clone(), (s.rules_on, s.active_rules.clone()));
            if s.rules_on > 0 {
                sites_on += 1;
                if s.level == "strict" {
                    sites_strict += 1;
                }
            } else {
                unprotected.push(SiteLink {
                    hosting_id: s.hosting_id.clone(),
                    domain: s.domain.clone(),
                    node_label: n.label.clone(),
                });
            }
            for c in &s.totals_24h {
                blocked_24h += c.hits;
                rule_tot.entry(c.rule.clone()).or_default().0 += c.hits;
            }
            for c in &s.totals_7d {
                blocked_7d += c.hits;
                rule_tot.entry(c.rule.clone()).or_default().1 += c.hits;
                *week_by_site_rule
                    .entry((s.hosting_id.clone(), c.rule.clone()))
                    .or_default() += c.hits;
            }
        }
        for h in &o.hourly {
            let e = hourly.entry(h.hour).or_default();
            if waf::counts_for_ban(&h.rule) {
                e.0 += h.hits;
            } else {
                e.1 += h.hits;
            }
        }
        all_bans.extend(o.bans.iter().map(|b| (n, b)));
    }
    unprotected.sort_by(|a, b| a.domain.cmp(&b.domain));

    let domain_of = |id: &str| sites.get(id).map(|s| s.0.clone());

    // ── Rules ──
    let mut rules: Vec<RuleRow> = rule_tot
        .into_iter()
        .map(|(rule, (day, week))| RuleRow {
            label: waf::label_for(&rule),
            bans: waf::counts_for_ban(&rule),
            rule,
            day,
            week,
        })
        .collect();
    rules.sort_by(|a, b| b.week.cmp(&a.week).then(a.rule.cmp(&b.rule)));

    // ── Tuning: one row per (site, rule) with refusals this week ──
    let mut tuning: Vec<TuneRow> = Vec::new();
    for n in nodes {
        let NodeAnswer::Overview(o) = &n.data else {
            continue;
        };
        for smp in &o.samples {
            let week = week_by_site_rule
                .get(&(smp.hosting_id.clone(), smp.rule.clone()))
                .copied()
                .unwrap_or(0);
            // The sample outlives the week (it is the last N refusals,
            // however old); a rule quiet all week is not worth tuning.
            if week == 0 {
                continue;
            }
            let Some(domain) = domain_of(&smp.hosting_id) else {
                continue;
            };
            let pinnable = waf::rule(&smp.rule).is_some();
            // No rules on at all: everything is off. Rules on but no list:
            // a node too old to report which, so unknown — not "off".
            let now_off = pinnable
                && active_rules.get(&smp.hosting_id).is_some_and(|(on, ids)| {
                    *on == 0 || (!ids.is_empty() && !ids.contains(&smp.rule))
                });
            let browser_pct = if smp.hits > 0 {
                smp.browser * 100 / smp.hits
            } else {
                0
            };
            tuning.push(TuneRow {
                node_id: n.node_id.clone(),
                hosting_id: smp.hosting_id.clone(),
                domain,
                label: waf::label_for(&smp.rule),
                rule: smp.rule.clone(),
                week,
                sample: smp.hits,
                browser_pct,
                ips: smp.ips,
                last_ago: super::stats::fmt_ago(&smp.last_ts),
                request: format!("{} {}", smp.method, smp.uri),
                suspect: pinnable
                    && !now_off
                    && smp.hits >= SUSPECT_MIN_SAMPLE
                    && smp.browser * 2 >= smp.hits,
                pinnable,
                now_off,
            });
        }
    }
    tuning.sort_by(|a, b| {
        b.suspect
            .cmp(&a.suspect)
            .then(b.week.cmp(&a.week))
            .then(a.domain.cmp(&b.domain))
    });
    let suspects = tuning.iter().filter(|t| t.suspect).count();
    tuning.truncate(TUNING_ROWS);

    // ── Bans ──
    let mut active_bans = Vec::new();
    let mut history = Vec::new();
    let mut active_by_ip: HashMap<String, String> = HashMap::new();
    let mut kinds: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut bans_7d = 0;
    let mut sorted = all_bans;
    sorted.sort_by(|a, b| b.1.banned_at.cmp(&a.1.banned_at));
    for (n, b) in sorted {
        let live = b.active && (b.expires_at == 0 || b.expires_at > now);
        let kind = ban_kind(&b.source, &b.reason);
        if b.banned_at >= since_7d {
            bans_7d += 1;
            *kinds.entry(kind).or_default() += 1;
        }
        let row = BanRow {
            node_id: n.node_id.clone(),
            node_label: n.label.clone(),
            ip: b.ip.clone(),
            kind,
            reason: b.reason.clone(),
            site: b
                .hosting_id
                .as_ref()
                .and_then(|h| domain_of(h).map(|d| (h.clone(), d))),
            banned_ago: super::stats::fmt_ago(&b.banned_at),
            expires: expires_label(b),
            ended: if live { String::new() } else { ended_label(b) },
        };
        if live {
            active_by_ip.entry(b.ip.clone()).or_insert_with(|| {
                if b.expires_at == 0 {
                    "banned permanently".to_string()
                } else {
                    format!("banned, lifts {}", super::stats::fmt_future(&b.expires_at))
                }
            });
            active_bans.push(row);
        } else if b.banned_at >= since_7d && history.len() < HISTORY_ROWS {
            history.push(row);
        }
    }
    let bans_7d_by_kind = kinds
        .iter()
        .rev()
        .map(|(k, n)| format!("{n} {}", k.to_lowercase()))
        .collect::<Vec<_>>()
        .join(" · ");

    // ── Addresses: merged across nodes ──
    struct IpAcc {
        hits: i64,
        browser: i64,
        sites: Vec<String>,
        rules: Vec<String>,
        last: i64,
    }
    let mut ip_acc: HashMap<String, IpAcc> = HashMap::new();
    for n in nodes {
        let NodeAnswer::Overview(o) = &n.data else {
            continue;
        };
        for a in &o.top_ips {
            let e = ip_acc.entry(a.ip.clone()).or_insert(IpAcc {
                hits: 0,
                browser: 0,
                sites: Vec::new(),
                rules: Vec::new(),
                last: 0,
            });
            e.hits += a.hits;
            e.browser += a.browser;
            e.last = e.last.max(a.last_ts);
            for s in &a.sites {
                let d = domain_of(s).unwrap_or_else(|| "a removed site".into());
                if !e.sites.contains(&d) {
                    e.sites.push(d);
                }
            }
            for r in &a.rules {
                let l = waf::label_for(r).to_string();
                if !e.rules.contains(&l) {
                    e.rules.push(l);
                }
            }
        }
    }
    let mut ips: Vec<IpRow> = ip_acc
        .into_iter()
        .map(|(ip, a)| IpRow {
            ban: active_by_ip.get(&ip).cloned(),
            browser: a.browser * 2 >= a.hits && a.hits > 0,
            sites: a.sites.join(", "),
            rules: a.rules.join(", "),
            last_ago: super::stats::fmt_ago(&a.last),
            hits: a.hits,
            ip,
        })
        .filter(|r| r.hits >= IP_MIN_HITS || r.ban.is_some())
        .collect();
    ips.sort_by(|a, b| b.hits.cmp(&a.hits).then(a.ip.cmp(&b.ip)));
    ips.truncate(IP_ROWS);

    // ── Verdict ──
    let (verdict_tone, verdict) = if sites_total == 0 && old_nodes.is_empty() {
        (
            "neutral",
            "No sites yet — nothing for the WAF to protect.".to_string(),
        )
    } else if sites_total > 0 && sites_on == 0 {
        (
            "warn",
            format!(
                "The WAF is off on all {sites_total} site{} — nothing is being filtered.",
                if sites_total == 1 { "" } else { "s" }
            ),
        )
    } else if suspects > 0 {
        (
            "warn",
            format!(
                "{suspects} rule{} may be turning away real visitors — see “Tuning” below.",
                if suspects == 1 { "" } else { "s" }
            ),
        )
    } else {
        (
            "ok",
            format!(
                "WAF on {sites_on} of {sites_total} sites · {blocked_24h} request{} refused in 24 h · {} address{} banned now.",
                if blocked_24h == 1 { "" } else { "s" },
                active_bans.len(),
                if active_bans.len() == 1 { "" } else { "es" }
            ),
        )
    };

    Page {
        verdict_tone,
        verdict,
        blocked_24h,
        blocked_7d,
        banned_now: active_bans.len(),
        bans_7d,
        bans_7d_by_kind,
        sites_total,
        sites_on,
        sites_strict,
        chart: build_chart(&hourly, now),
        rules,
        tuning,
        suspects,
        ips,
        active_bans,
        history,
        unprotected,
        fail2ban_off,
        old_nodes,
    }
}

#[derive(Template)]
#[template(path = "protection.html")]
struct ProtectionTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    p: Page,
    can_tune: bool,
    flash: Option<String>,
    flash_error: Option<String>,
    csrf_token: String,
    node_auth_warning: Option<String>,
    /// Nodes that did not answer at all (not an authentication failure —
    /// that one has its own banner).
    unreachable: Vec<String>,
}

#[derive(Deserialize, Default)]
pub struct ProtectionQuery {
    #[serde(default)]
    pub flash: Option<String>,
    #[serde(default)]
    pub flash_error: Option<String>,
}

/// Ask one node; an older one that cannot decode `WafOverview` (it drops
/// the connection) still gives its active bans.
async fn ask(state: &SharedState, node: Option<&str>) -> Result<NodeAnswer, String> {
    let resp = match node {
        None => hyperion_rpc_client::call(&state.agent_socket, Request::WafOverview { days: DAYS })
            .await
            .map_err(|e| e.to_string()),
        Some(id) => crate::dispatcher::dispatch_to_node(
            state,
            Some(id),
            Request::WafOverview { days: DAYS },
        )
        .await
        .map_err(|e| e.to_string()),
    };
    if let Ok(RpcResponse::WafOverview(o)) = resp {
        return Ok(NodeAnswer::Overview(o));
    }
    let bans = match node {
        None => {
            hyperion_rpc_client::call(&state.agent_socket, Request::BanList { hosting_id: None })
                .await
                .map_err(|e| e.to_string())
        }
        Some(id) => crate::dispatcher::dispatch_to_node(
            state,
            Some(id),
            Request::BanList { hosting_id: None },
        )
        .await
        .map_err(|e| e.to_string()),
    };
    match bans {
        Ok(RpcResponse::BanList(b)) => Ok(NodeAnswer::BansOnly(b)),
        Ok(RpcResponse::Error(e)) => Err(e.to_string()),
        Ok(_) => Err("unexpected response".into()),
        Err(e) => Err(e),
    }
}

pub async fn get_protection(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    axum::extract::Query(q): axum::extract::Query<ProtectionQuery>,
) -> Result<Response, AppError> {
    // Cluster-wide view: all-hostings scope (tenant roles with
    // SecurityManage act only on their own hostings).
    if !(ctx.can(Capability::SecurityManage) && ctx.scope_all()) {
        return Ok(Redirect::to("/?flash_error=admin+role+required").into_response());
    }
    let mut nodes: Vec<NodeData> = Vec::new();
    let mut unreachable: Vec<String> = Vec::new();
    match ask(&state, None).await {
        Ok(data) => nodes.push(NodeData {
            node_id: "local".into(),
            label: "master".into(),
            data,
        }),
        Err(e) => {
            tracing::warn!(error = %e, "protection: the master's own agent did not answer");
            unreachable.push("master".into());
        }
    }
    let mut node_auth_warning = None;
    if let Ok(RpcResponse::NodesList(list)) = crate::dispatcher::cached_nodes(&state)
        .await
        .map(hyperion_rpc::codec::Response::NodesList)
    {
        let (answered, failed) =
            crate::dispatcher::fan_out_reporting(&state, list, Request::WafOverview { days: DAYS })
                .await;
        for (n, resp) in answered {
            let data = match resp {
                RpcResponse::WafOverview(o) => NodeAnswer::Overview(o),
                // Answered, but not with an overview (an error from a node
                // mid-upgrade): fall back to its bans like an old node.
                _ => match ask(&state, Some(n.node_id.as_str())).await {
                    Ok(d) => d,
                    Err(_) => {
                        unreachable.push(n.label.clone());
                        continue;
                    }
                },
            };
            nodes.push(NodeData {
                node_id: n.node_id,
                label: n.label,
                data,
            });
        }
        node_auth_warning = super::node_auth_warning(&failed);
        for (n, e) in failed {
            if matches!(
                e,
                crate::dispatcher::DispatchError::ResponseAuthFailed { .. }
            ) {
                continue;
            }
            // Dropped the connection: most likely too old to decode the
            // request. Its bans still count.
            match ask(&state, Some(n.node_id.as_str())).await {
                Ok(data) => nodes.push(NodeData {
                    node_id: n.node_id,
                    label: n.label,
                    data,
                }),
                Err(_) => unreachable.push(n.label),
            }
        }
    }
    nodes.sort_by(|a, b| a.node_id.cmp(&b.node_id));

    let tpl = ProtectionTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "protection",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        p: build(&nodes, chrono::Utc::now().timestamp()),
        can_tune: ctx.can(Capability::HostingEditConfig),
        flash: q.flash.filter(|s| !s.is_empty()),
        flash_error: q.flash_error.filter(|s| !s.is_empty()),
        csrf_token: super::session_csrf_token(&state, &ctx),
        node_auth_warning,
        unreachable,
    };
    Ok(Html(tpl.render()?).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperion_types::waf::{
        WafHourCount, WafIpActivity, WafRuleCount, WafRuleSample, WafSiteFacts,
    };

    const NOW: i64 = 1_800_000_000;

    fn site(id: &str, domain: &str, level: &str, rules_on: u32) -> WafSiteFacts {
        WafSiteFacts {
            hosting_id: id.into(),
            domain: domain.into(),
            level: level.into(),
            rules_on,
            ..Default::default()
        }
    }

    fn count(rule: &str, hits: i64) -> WafRuleCount {
        WafRuleCount {
            rule: rule.into(),
            hits,
        }
    }

    fn sample(id: &str, rule: &str, hits: i64, browser: i64) -> WafRuleSample {
        WafRuleSample {
            hosting_id: id.into(),
            rule: rule.into(),
            hits,
            browser,
            ips: 3,
            last_ts: NOW - 60,
            method: "GET".into(),
            uri: "/x".into(),
        }
    }

    fn ban(ip: &str, at: i64, active: bool, end: Option<&str>, reason: &str) -> IpBanWire {
        IpBanWire {
            ip: ip.into(),
            reason: reason.into(),
            source: "auto".into(),
            banned_at: at,
            expires_at: at + 3600,
            active,
            end_reason: end.map(str::to_string),
            ..Default::default()
        }
    }

    fn node(id: &str, o: WafOverview) -> NodeData {
        NodeData {
            node_id: id.into(),
            label: id.into(),
            data: NodeAnswer::Overview(o),
        }
    }

    #[test]
    fn merges_nodes_and_counts_coverage() {
        let mut a = WafOverview {
            fail2ban_enabled: true,
            ..Default::default()
        };
        let mut s1 = site("h1", "one.cz", "standard", 6);
        s1.totals_24h = vec![count("probe_args", 4)];
        s1.totals_7d = vec![count("probe_args", 10), count("xmlrpc", 2)];
        a.sites = vec![s1, site("h2", "two.cz", "off", 0)];
        a.hourly = vec![
            WafHourCount {
                hour: NOW - NOW % 3600,
                rule: "probe_args".into(),
                hits: 3,
            },
            WafHourCount {
                hour: NOW - NOW % 3600,
                rule: "xmlrpc".into(),
                hits: 1,
            },
        ];
        a.top_ips = vec![WafIpActivity {
            ip: "9.9.9.9".into(),
            hits: 5,
            sites: vec!["h1".into()],
            rules: vec!["probe_args".into()],
            last_ts: NOW - 30,
            ..Default::default()
        }];
        a.bans = vec![ban("9.9.9.9", NOW - 100, true, None, "auto: WAF refusals")];
        let mut s3 = site("h3", "three.cz", "strict", 11);
        s3.totals_7d = vec![count("probe_args", 1)];
        let b = WafOverview {
            fail2ban_enabled: false,
            sites: vec![s3],
            top_ips: vec![WafIpActivity {
                ip: "9.9.9.9".into(),
                hits: 2,
                sites: vec!["h3".into()],
                rules: vec!["dotfiles".into()],
                last_ts: NOW - 10,
                ..Default::default()
            }],
            ..Default::default()
        };
        let p = build(&[node("local", a), node("w1", b)], NOW);

        assert_eq!((p.sites_total, p.sites_on, p.sites_strict), (3, 2, 1));
        assert_eq!(p.unprotected.len(), 1);
        assert_eq!(p.unprotected[0].domain, "two.cz");
        assert_eq!((p.blocked_24h, p.blocked_7d), (4, 13));
        assert_eq!(p.rules[0].rule, "probe_args");
        assert_eq!(p.rules[0].week, 11, "summed across nodes");
        assert!(p.rules[0].bans && !p.rules[1].bans);
        assert_eq!(p.fail2ban_off, vec!["w1".to_string()]);

        assert_eq!(p.ips.len(), 1);
        let ip = &p.ips[0];
        assert_eq!(ip.hits, 7, "one address merged across nodes");
        assert_eq!(ip.sites, "one.cz, three.cz");
        assert!(ip.ban.is_some(), "its active ban is shown beside it");

        assert!(p.chart.has_data);
        assert_eq!(p.chart.peak, 4);
        assert_eq!(p.chart.bars.len(), 1);
        assert_eq!(p.verdict_tone, "ok");
    }

    #[test]
    fn a_rule_already_turned_off_is_no_longer_a_suspect() {
        let mut s = site("h1", "one.cz", "strict", 10);
        s.active_rules = vec!["probe_args".into()];
        s.totals_7d = vec![count("author_enum", 40)];
        let o = WafOverview {
            sites: vec![s],
            samples: vec![sample("h1", "author_enum", 20, 20)],
            ..Default::default()
        };
        let p = build(&[node("local", o)], NOW);
        assert_eq!(p.suspects, 0);
        assert!(p.tuning[0].now_off && !p.tuning[0].suspect);
        assert_eq!(p.verdict_tone, "ok");

        // The whole WAF switched off since: every rule is off.
        let mut s = site("h1", "one.cz", "off", 0);
        s.totals_7d = vec![count("author_enum", 40)];
        let o = WafOverview {
            sites: vec![s],
            samples: vec![sample("h1", "author_enum", 20, 20)],
            ..Default::default()
        };
        let p = build(&[node("local", o)], NOW);
        assert!(p.tuning[0].now_off);
    }

    #[test]
    fn a_quiet_address_is_not_busy_unless_banned() {
        let act = |ip: &str, hits| WafIpActivity {
            ip: ip.into(),
            hits,
            ..Default::default()
        };
        let o = WafOverview {
            top_ips: vec![act("1.1.1.1", 2), act("2.2.2.2", 9), act("3.3.3.3", 1)],
            bans: vec![ban("3.3.3.3", NOW - 60, true, None, "auto: WAF refusals")],
            ..Default::default()
        };
        let p = build(&[node("local", o)], NOW);
        let ips: Vec<&str> = p.ips.iter().map(|i| i.ip.as_str()).collect();
        assert_eq!(ips, vec!["2.2.2.2", "3.3.3.3"]);
    }

    #[test]
    fn mostly_browser_traffic_is_a_suspect_but_only_for_real_rules() {
        // rules_on but no list: an older node, so "in force" is unknown.
        let mut s = site("h1", "one.cz", "strict", 11);
        s.totals_7d = vec![
            count("author_enum", 40),
            count("probe_args", 90),
            count("geo", 500),
            count("dotfiles", 3),
        ];
        let o = WafOverview {
            sites: vec![s],
            samples: vec![
                sample("h1", "author_enum", 20, 15), // browsers: suspect
                sample("h1", "probe_args", 50, 2),   // scripts: fine
                sample("h1", "geo", 50, 50),         // chosen on purpose
                sample("h1", "dotfiles", 3, 3),      // too few to say
                sample("h1", "xmlrpc", 9, 9),        // nothing this week
            ],
            ..Default::default()
        };
        let p = build(&[node("local", o)], NOW);
        assert_eq!(p.suspects, 1);
        assert_eq!(p.tuning[0].rule, "author_enum", "suspects sort first");
        assert_eq!(p.tuning[0].browser_pct, 75);
        assert!(p.tuning.iter().all(|t| t.rule != "xmlrpc"));
        let geo = p.tuning.iter().find(|t| t.rule == "geo").expect("geo");
        assert!(!geo.suspect && !geo.pinnable);
        assert!(p.tuning.iter().all(|t| !t.now_off), "no rule list: unknown");
        assert_eq!(p.verdict_tone, "warn");
        assert!(p.verdict.contains("1 rule may"));
    }

    #[test]
    fn bans_split_into_active_and_history_with_how_they_ended() {
        let o = WafOverview {
            bans: vec![
                ban("1.1.1.1", NOW - 60, true, None, "auto: ssh brute force"),
                ban(
                    "2.2.2.2",
                    NOW - 7200,
                    false,
                    Some("expired"),
                    "auto: WAF refusals",
                ),
                ban(
                    "3.3.3.3",
                    NOW - 9000,
                    false,
                    Some("lifted"),
                    "auto: ftp brute force",
                ),
                ban("4.4.4.4", NOW - 9 * 86_400, false, Some("expired"), "x"),
                // Marked active but already past its time: not in force.
                ban(
                    "5.5.5.5",
                    NOW - 5000,
                    true,
                    None,
                    "auto: mail (smtp/imap) brute force",
                ),
            ],
            ..Default::default()
        };
        let p = build(&[node("local", o)], NOW);
        assert_eq!(p.active_bans.len(), 1);
        assert_eq!(p.active_bans[0].kind, "SSH");
        let ips: Vec<&str> = p.history.iter().map(|b| b.ip.as_str()).collect();
        assert_eq!(ips, vec!["5.5.5.5", "2.2.2.2", "3.3.3.3"], "newest first");
        assert_eq!(p.history[0].ended, "ran out", "lapsed, not yet swept");
        assert_eq!(p.history[1].ended, "ran out");
        assert_eq!(p.history[1].kind, "WAF");
        assert!(p.history[2].ended.starts_with("lifted"));
        assert_eq!(p.bans_7d, 4, "the 9-day-old one is outside the week");
    }

    #[test]
    fn an_old_node_still_shows_its_active_bans() {
        let nodes = [NodeData {
            node_id: "w9".into(),
            label: "old-box".into(),
            data: NodeAnswer::BansOnly(vec![IpBanWire {
                ip: "7.7.7.7".into(),
                source: "manual".into(),
                banned_at: NOW - 10,
                expires_at: 0,
                active: true,
                ..Default::default()
            }]),
        }];
        let p = build(&nodes, NOW);
        assert_eq!(p.old_nodes, vec!["old-box".to_string()]);
        assert_eq!(p.active_bans.len(), 1);
        assert_eq!(p.active_bans[0].kind, "Manual");
        assert_eq!(p.active_bans[0].expires, "permanent");
    }

    #[test]
    fn verdict_says_when_every_site_is_unprotected() {
        let o = WafOverview {
            sites: vec![site("h1", "a.cz", "off", 0), site("h2", "b.cz", "off", 0)],
            ..Default::default()
        };
        let p = build(&[node("local", o)], NOW);
        assert_eq!(p.verdict_tone, "warn");
        assert!(p.verdict.contains("off on all 2 sites"), "{}", p.verdict);
        assert!(!p.chart.has_data);
    }

    #[test]
    fn the_page_renders_every_section() {
        let mut s = site("h1", "one.cz", "strict", 11);
        s.totals_24h = vec![count("author_enum", 9)];
        s.totals_7d = vec![count("author_enum", 40)];
        let o = WafOverview {
            fail2ban_enabled: false,
            sites: vec![s, site("h2", "<b>two</b>.cz", "off", 0)],
            hourly: vec![WafHourCount {
                hour: NOW - NOW % 3600 - 7200,
                rule: "author_enum".into(),
                hits: 9,
            }],
            samples: vec![WafRuleSample {
                uri: "/?author=1<script>".into(),
                ..sample("h1", "author_enum", 20, 15)
            }],
            top_ips: vec![WafIpActivity {
                ip: "9.9.9.9".into(),
                hits: 20,
                browser: 15,
                sites: vec!["h1".into()],
                rules: vec!["author_enum".into()],
                last_ts: NOW - 5,
            }],
            bans: vec![
                ban("9.9.9.9", NOW - 60, true, None, "auto: WAF refusals"),
                ban(
                    "8.8.4.4",
                    NOW - 7200,
                    false,
                    Some("lifted"),
                    "auto: ssh brute force",
                ),
            ],
            ..Default::default()
        };
        let p = build(&[node("local", o)], NOW);
        let html = ProtectionTpl {
            username: "kevin",
            user_initial: 'k',
            active: "protection",
            css_version: "t",
            htmx_version: "t",
            p,
            can_tune: true,
            flash: None,
            flash_error: None,
            csrf_token: "tok".into(),
            node_auth_warning: None,
            unreachable: vec!["w2".into()],
        }
        .render()
        .expect("render");
        for needle in [
            "possible false positive",
            "name=\"from\" value=\"protection\"",
            "action=\"/bans/unban\"",
            "Ban history",
            "Sites without the WAF",
            "Automatic bans off on",
            "No answer from w2",
            "class=\"prot-ban\"",
        ] {
            assert!(html.contains(needle), "missing {needle:?}");
        }
        assert!(!html.contains("<script>\"") && !html.contains("author=1<script>"));
        assert!(!html.contains("<b>two</b>"), "domains are escaped");
    }

    #[test]
    fn ban_kinds_from_the_scanner_reasons() {
        assert_eq!(ban_kind("auto", "auto: WAF refusals"), "WAF");
        assert_eq!(
            ban_kind("auto", "auto: wp-login / xmlrpc brute force"),
            "Login flood"
        );
        assert_eq!(ban_kind("auto", "auto: ssh brute force"), "SSH");
        assert_eq!(ban_kind("manual", "auto: ssh"), "Manual");
        assert_eq!(ban_kind("auto", "something new"), "Automatic");
    }
}
