//! The hostings list.

use super::*;

#[derive(Template)]
#[template(path = "hostings_list.html")]
pub(super) struct ListTpl<'a> {
    pub(super) username: &'a str,
    pub(super) user_initial: char,
    pub(super) active: &'static str,
    pub(super) css_version: &'static str,
    pub(super) htmx_version: &'static str,
    /// One pre-computed view row per hosting — see [`ListRow`].
    pub(super) rows: Vec<ListRow>,
    /// Segment counts over the rows this user can see AND that match
    /// the search — so the numbers on the filter strip agree with what
    /// clicking them shows.
    pub(super) counts: ListCounts,
    pub(super) total_count: usize,
    pub(super) q: String,
    pub(super) state_filter: String,
    /// Currently active sort column ("" / "domain" / "created" /
    /// "state" / "node"). Template uses this to render the up/down
    /// arrow on the active column header.
    pub(super) sort_key: String,
    /// "asc" | "desc" — passed through the URL so the operator can
    /// flip the direction by re-clicking the same column.
    pub(super) sort_dir: String,
    pub(super) csrf_token: String,
    pub(super) csrf_bulk: String,
    pub(super) error: Option<String>,
    pub(super) flash: Option<String>,
    /// WP asset library — drives the "Bulk install asset" dropdown.
    /// Empty list = the dropdown hides itself.
    pub(super) wp_assets: Vec<hyperion_types::WpAssetSummary>,
    /// Set when a node's response failed authentication and its
    /// hostings were therefore discarded — the list below is INCOMPLETE.
    /// Rendered by `_node_auth_banner.html`.
    pub(super) node_auth_warning: Option<String>,
    /// A test site can be made — shows the "Test website" button.
    pub(super) test_available: bool,
}

/// A certificate this close to expiry counts as needing attention.
/// Auto-renew runs at 30 days, so a cert still under 14 means renewal
/// has been failing for over two weeks.
pub(super) const CERT_ATTENTION_DAYS: i64 = 14;

/// One row of the hostings list, with every label and flag worked out
/// server-side: askama can't call closures, and keeping the rules here
/// means the "needs attention" filter and the row badges can never
/// disagree about what counts.
pub(super) struct ListRow {
    pub(super) s: HostingSummary,
    /// Node is listed in `cluster.test_node_ids`.
    pub(super) is_test: bool,
    /// Node heartbeat is older than UNREACHABLE_HEARTBEAT_SECS.
    pub(super) is_unreachable: bool,
    /// "WordPress 6.6" / "PHP 8.3" / "Static" / "Proxy" / "Redirect";
    /// empty when the owning node is too old to report a type.
    pub(super) type_label: String,
    /// "54 days left" / "expired" / "self-signed"; empty = no cert.
    pub(super) cert_label: String,
    /// "ok" | "warn" | "err" pill class for the certificate cell.
    pub(super) cert_class: &'static str,
    /// Why this row is in "Needs attention" — empty when it isn't.
    /// Shown as the row's tooltip-free reason line under the domain.
    pub(super) attention: Vec<&'static str>,
}

impl ListRow {
    pub(super) fn new(s: HostingSummary, is_test: bool, is_unreachable: bool, now: i64) -> Self {
        let type_label = match s.kind.as_deref() {
            Some("static") => "Static".to_string(),
            Some("reverse_proxy") => "Proxy".to_string(),
            Some("redirect") => "Redirect".to_string(),
            Some(_) | None => match (&s.wp_version, &s.php_version) {
                (Some(wp), _) => format!("WordPress {wp}"),
                (None, Some(php)) => format!("PHP {php}"),
                // An old node reports no kind; a PHP-less row there is
                // most likely static, but don't claim it.
                (None, None) if s.kind.is_none() => String::new(),
                (None, None) => "Static".to_string(),
            },
        };
        let cert_days = s.cert_not_after.map(|t| (t - now).div_euclid(86_400));
        let self_signed = s.cert_issuer.as_deref() == Some("self-signed");
        let cert_class = match cert_days {
            Some(d) if d < 0 => "err",
            Some(d) if d < CERT_ATTENTION_DAYS => "warn",
            Some(_) if self_signed => "warn",
            Some(_) => "ok",
            None => "",
        };
        let cert_label = match cert_days {
            None => String::new(),
            Some(d) if d < 0 => "expired".to_string(),
            Some(_) if self_signed => "self-signed".to_string(),
            Some(1) => "1 day left".to_string(),
            Some(d) => format!("{d} days left"),
        };
        let mut attention = Vec::new();
        if s.state == hyperion_types::HostingState::Failed {
            attention.push("provisioning failed");
        }
        if is_unreachable {
            attention.push("node offline");
        }
        match cert_days {
            Some(d) if d < 0 => attention.push("certificate expired"),
            Some(d) if d < CERT_ATTENTION_DAYS => attention.push("certificate expiring"),
            _ => {}
        }
        if s.last_backup_ok == Some(false) {
            attention.push("last backup failed");
        }
        // A branch with published holes that will never be fixed (8.1): the
        // site is exposed whatever its node runs.
        if s.php_version
            .is_some_and(|v| hyperion_types::php_security::branch_unfixable(v.as_str()))
        {
            attention.push("PHP without security fixes");
        }
        Self {
            s,
            is_test,
            is_unreachable,
            type_label,
            cert_label,
            cert_class,
            attention,
        }
    }

    pub(super) fn needs_attention(&self) -> bool {
        !self.attention.is_empty()
    }

    /// Joined reasons for the template ("node offline · last backup failed").
    pub(super) fn attention_text(&self) -> String {
        self.attention.join(" · ")
    }
}

#[derive(Default)]
pub(super) struct ListCounts {
    pub(super) all: usize,
    pub(super) active: usize,
    pub(super) suspended: usize,
    pub(super) failed: usize,
    pub(super) attention: usize,
}

#[derive(Deserialize, Default)]
pub struct ListQuery {
    #[serde(default)]
    pub q: String,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub bulk_flash: Option<String>,
    /// Sort column. Empty / unknown ⇒ `domain` (alphabetical), the
    /// default the list shipped with. Accepted: `domain`, `created`,
    /// `updated`, `state`, `node`, `disk`.
    #[serde(default)]
    pub sort: String,
    /// `asc` | `desc`. Empty ⇒ `asc` for textual columns,
    /// `desc` for time/numeric (newest/largest first).
    #[serde(default)]
    pub dir: String,
}

pub async fn get_list(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    axum::extract::Query(q): axum::extract::Query<ListQuery>,
) -> Result<Response, AppError> {
    let (rows, dropped) = list_hostings_reporting(&state)
        .await
        .map_err(AppError::Rpc)?;
    let node_auth_warning = crate::handlers::node_auth_warning(&dropped);
    // Role-based filter: operators + viewers only see hostings they
    // have an explicit access grant for. super_admin + admin see all.
    // The total is taken AFTER this, so a tenant's "N hostings" counts
    // their own sites, not the whole cluster's.
    let rows = filter_by_access(&state, &ctx, rows).await;
    let total_count = rows.len();
    let needle = q.q.trim().to_lowercase();
    let state_filter = q.state.trim().to_lowercase();

    // Pre-tag each row with `is_on_test_node` + `is_on_unreachable_node`
    // so the template can render the TEST chip + offline pill without
    // doing closure-based set lookups (askama can't parse Rust closures).
    let (master_hostname, cluster_cfg) = fetch_master_and_cluster(&state).await;
    let mut test_set: std::collections::HashSet<String> = cluster_cfg
        .test_node_ids
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    // The master may be listed as `local` or by hostname, and its rows
    // carry either (or no node id at all) — a test master tags them all.
    if is_master_test(&cluster_cfg, &master_hostname) {
        test_set.insert(crate::dispatcher::LOCAL_NODE_SENTINEL.to_string());
        if !master_hostname.is_empty() {
            test_set.insert(master_hostname.clone());
        }
    }
    let test_available = fetch_test_setup(&state).await.available();
    // Compute "unreachable" set: any node whose last_seen_at heartbeat
    // is more than UNREACHABLE_HEARTBEAT_SECS old. The agent posts
    // heartbeats every ~30s; 5 min of silence is a clear "the worker
    // is gone" signal. Best-effort — if NodesList errors we just
    // tag nothing (graceful degradation).
    const UNREACHABLE_HEARTBEAT_SECS: i64 = 300;
    let now_secs = hyperion_types::now_secs();
    let unreachable_set: std::collections::HashSet<String> =
        match crate::dispatcher::cached_nodes(&state)
            .await
            .map(hyperion_rpc::codec::Response::NodesList)
        {
            Ok(RpcResponse::NodesList(ns)) => ns
                .into_iter()
                .filter(|n| {
                    n.last_seen_at > 0 && (now_secs - n.last_seen_at) > UNREACHABLE_HEARTBEAT_SECS
                })
                .map(|n| n.node_id)
                .collect(),
            _ => std::collections::HashSet::new(),
        };
    let on = |set: &std::collections::HashSet<String>, r: &HostingSummary| {
        r.node_id.as_ref().is_some_and(|n| set.contains(n))
    };
    let on_test = |r: &HostingSummary| {
        test_set.contains(
            r.node_id
                .as_deref()
                .unwrap_or(crate::dispatcher::LOCAL_NODE_SENTINEL),
        )
    };
    let searched: Vec<ListRow> = rows
        .into_iter()
        .filter(|r| needle.is_empty() || r.domain.to_lowercase().contains(&needle))
        .map(|r| {
            let (t, u) = (on_test(&r), on(&unreachable_set, &r));
            ListRow::new(r, t, u, now_secs)
        })
        .collect();
    let mut counts = ListCounts {
        all: searched.len(),
        ..Default::default()
    };
    for r in &searched {
        match r.s.state.as_str() {
            "active" => counts.active += 1,
            "suspended" => counts.suspended += 1,
            "failed" => counts.failed += 1,
            _ => {}
        }
        if r.needs_attention() {
            counts.attention += 1;
        }
    }
    let mut rows: Vec<ListRow> = searched
        .into_iter()
        .filter(|r| match state_filter.as_str() {
            "" => true,
            "attention" => r.needs_attention(),
            s => r.s.state.as_str() == s,
        })
        .collect();

    // ── Server-side sort ──
    //
    // Defaults to alphabetical-by-domain; explicit ?sort= overrides,
    // with ?dir= flipping the comparator. Missing values (no cert, never
    // sampled, never backed up) sort as the smallest, so "asc" on cert
    // or backup puts the sites with nothing on record first.
    let sort_key = q.sort.trim().to_lowercase();
    let dir_desc = match q.dir.trim().to_lowercase().as_str() {
        "desc" => Some(true),
        "asc" => Some(false),
        _ => None,
    };
    // Default direction per column — alphabetical = asc; time = newest
    // first; disk = largest first; cert = soonest expiry first (asc).
    let desc = dir_desc.unwrap_or(matches!(
        sort_key.as_str(),
        "created" | "updated" | "disk" | "backup"
    ));
    match sort_key.as_str() {
        "created" => rows.sort_by_key(|r| r.s.created_at),
        "state" => rows.sort_by(|a, b| a.s.state.as_str().cmp(b.s.state.as_str())),
        "node" => rows.sort_by(|a, b| {
            a.s.node_id
                .as_deref()
                .unwrap_or("")
                .cmp(b.s.node_id.as_deref().unwrap_or(""))
        }),
        "disk" => rows.sort_by_key(|r| r.s.disk_bytes),
        "cert" => rows.sort_by_key(|r| r.s.cert_not_after),
        "backup" => rows.sort_by_key(|r| r.s.last_backup_at),
        // Default + "domain" both fall here.
        _ => rows.sort_by_key(|a| a.s.domain.to_lowercase()),
    }
    if desc {
        rows.reverse();
    }
    let csrf_token = csrf_token_for(&state, &ctx, "/hostings/delete");
    let csrf_bulk = csrf_token_for(&state, &ctx, "/hostings/bulk");
    let tpl = ListTpl {
        username: &ctx.username,
        user_initial: crate::handlers::user_initial(&ctx.username),
        active: "hostings",
        css_version: crate::handlers::css_version(),
        htmx_version: crate::handlers::htmx_version(),
        rows,
        counts,
        total_count,
        q: q.q,
        state_filter,
        sort_key: if sort_key.is_empty() {
            "domain".to_string()
        } else {
            sort_key
        },
        sort_dir: if desc { "desc".into() } else { "asc".into() },
        csrf_token,
        csrf_bulk,
        error: None,
        flash: q.bulk_flash,
        wp_assets: fetch_wp_assets(&state).await.unwrap_or_default(),
        node_auth_warning,
        test_available,
    };
    Ok(Html(tpl.render()?).into_response())
}

#[cfg(test)]
mod list_row_tests {
    use super::*;
    use hyperion_types::{HostingId, HostingState};

    const NOW: i64 = 1_800_000_000;

    fn summary() -> HostingSummary {
        HostingSummary {
            id: HostingId("h1".into()),
            domain: "ex.cz".into(),
            state: HostingState::Active,
            php_version: Some(PhpVersion::V8_3),
            created_at: 0,
            node_id: Some("n1".into()),
            maintenance_mode: false,
            kind: Some("php".into()),
            wp_version: None,
            cert_not_after: Some(NOW + 60 * 86_400),
            cert_issuer: Some("letsencrypt".into()),
            disk_bytes: None,
            last_backup_at: None,
            last_backup_ok: None,
        }
    }

    #[test]
    fn type_label_prefers_wordpress_then_php_then_kind() {
        let mut s = summary();
        assert_eq!(
            ListRow::new(s.clone(), false, false, NOW).type_label,
            "PHP 8.3"
        );
        s.wp_version = Some("6.6.2".into());
        assert_eq!(
            ListRow::new(s.clone(), false, false, NOW).type_label,
            "WordPress 6.6.2"
        );
        s.kind = Some("reverse_proxy".into());
        assert_eq!(
            ListRow::new(s.clone(), false, false, NOW).type_label,
            "Proxy"
        );
        // An old node reports no kind: don't guess "Static".
        let mut old = summary();
        old.kind = None;
        old.php_version = None;
        assert_eq!(ListRow::new(old, false, false, NOW).type_label, "");
    }

    #[test]
    fn healthy_row_needs_no_attention() {
        let r = ListRow::new(summary(), false, false, NOW);
        assert!(!r.needs_attention());
        assert_eq!(r.cert_class, "ok");
        assert_eq!(r.cert_label, "60 days left");
    }

    #[test]
    fn each_problem_lands_in_attention() {
        let mut s = summary();
        s.state = HostingState::Failed;
        s.cert_not_after = Some(NOW - 1);
        s.last_backup_ok = Some(false);
        let r = ListRow::new(s, false, true, NOW);
        assert_eq!(
            r.attention_text(),
            "provisioning failed · node offline · certificate expired · last backup failed"
        );
        assert_eq!(r.cert_class, "err");
        assert_eq!(r.cert_label, "expired");
    }

    #[test]
    fn a_site_on_an_unfixable_php_needs_attention() {
        let mut s = summary();
        s.php_version = Some(hyperion_types::PhpVersion::V8_1);
        let r = ListRow::new(s, false, false, NOW);
        assert_eq!(r.attention, vec!["PHP without security fixes"]);
    }

    #[test]
    fn cert_inside_window_is_expiring() {
        let mut s = summary();
        s.cert_not_after = Some(NOW + 3 * 86_400 + 10);
        let r = ListRow::new(s, false, false, NOW);
        assert_eq!(r.attention, vec!["certificate expiring"]);
        assert_eq!(r.cert_class, "warn");
        assert_eq!(r.cert_label, "3 days left");
    }

    #[test]
    fn self_signed_warns_but_is_not_attention() {
        let mut s = summary();
        s.cert_issuer = Some("self-signed".into());
        let r = ListRow::new(s, false, false, NOW);
        assert_eq!(r.cert_class, "warn");
        assert_eq!(r.cert_label, "self-signed");
        assert!(!r.needs_attention());
    }
}
