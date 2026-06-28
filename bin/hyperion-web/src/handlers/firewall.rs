//! `/firewall` — cluster-wide firewall ruleset overview.
//!
//! Fans out `FirewallList` RPC to the master + every enrolled
//! worker. Per node we show:
//!
//!   - which backend answered (nft / iptables / unknown)
//!   - the parsed "open ports" pill row (best-effort)
//!   - the full raw ruleset inside a collapsed `<details>`
//!
//! Read-only by design. The operator inspects via this page,
//! mutates via SSH + nft / firewalld / ufw — we don't ship a
//! rule editor because the risk of bricking remote access by
//! accidentally locking yourself out is too high to justify a
//! GUI button for. The "View" gives 80% of the value of a
//! full editor (catching unexpected open ports, drift between
//! nodes) at 0% of the risk.

use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::state::SharedState;
use askama::Template;
use axum::extract::State;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Form;
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use hyperion_state::capabilities::Capability;
use serde::Deserialize;

#[derive(Template)]
#[template(path = "firewall.html")]
struct FirewallTpl<'a> {
    username: &'a str,
    user_initial: char,
    active: &'static str,
    css_version: &'static str,
    htmx_version: &'static str,
    /// One entry per node — master first, then workers in node_id
    /// order so the page is deterministic.
    nodes: Vec<NodeFirewall>,
    /// Hardcoded "open these together" port sets. Rendered as
    /// collapsible cards under the per-node section so an operator
    /// who needs to "open mail on this box" copies one snippet
    /// instead of looking up port numbers.
    templates: Vec<PortTemplate>,
    /// Slim list `(node_id, label, applyable)` for the per-template
    /// "Apply on…" button row. `applyable=false` for nodes that
    /// can't be reached or that are drained — operator sees the
    /// button greyed out so they know the option exists but isn't
    /// runnable right now.
    apply_targets: Vec<ApplyTarget>,
    /// Cluster-wide posture roll-up rendered at the top of the page.
    summary: FwSummary,
    csrf_token: String,
}

pub struct ApplyTarget {
    pub node_id: String,
    pub label: String,
    pub applyable: bool,
}

/// One recent ban shown inline on a node card.
pub struct BanLine {
    pub ip: String,
    pub reason: String,
    pub source: String,
    pub expires_at: i64,
}

/// Cluster-wide firewall posture summary (top-of-page KPIs).
pub struct FwSummary {
    pub nodes_total: usize,
    pub nodes_reachable: usize,
    pub ban_total: usize,
    pub ban_auto: usize,
    pub ban_manual: usize,
    pub open_ports_total: usize,
}

pub struct NodeFirewall {
    pub node_id: String,
    pub label: String,
    pub view: hyperion_types::FirewallView,
    /// True when the RPC failed entirely — render a "node
    /// unreachable" notice instead of an empty card.
    pub unreachable: bool,
    /// Drained nodes are intentionally quiet, not broken.
    pub drained: bool,
    pub drain_reason: String,
    /// Active nftables bans on this node (from BanList).
    pub ban_total: usize,
    pub ban_auto: usize,
    pub ban_manual: usize,
    pub ban_v4: usize,
    pub ban_v6: usize,
    /// Newest few bans, for an at-a-glance "who's being dropped".
    pub recent_bans: Vec<BanLine>,
}

/// Fold a node's ban list into counts + the newest 3 for display.
fn summarize_bans(
    mut bans: Vec<hyperion_types::IpBanWire>,
) -> (usize, usize, usize, usize, usize, Vec<BanLine>) {
    let total = bans.len();
    let auto = bans.iter().filter(|b| b.source == "auto").count();
    let v6 = bans.iter().filter(|b| b.ip.contains(':')).count();
    bans.sort_by(|a, b| b.banned_at.cmp(&a.banned_at));
    let recent = bans
        .into_iter()
        .take(3)
        .map(|b| BanLine {
            ip: b.ip,
            reason: b.reason,
            source: b.source,
            expires_at: b.expires_at,
        })
        .collect();
    (total, auto, total - auto, total - v6, v6, recent)
}

pub struct PortTemplate {
    pub name: &'static str,
    pub ports_summary: &'static str,
    pub description: &'static str,
    pub snippet: &'static str,
    /// Stable id used by the Apply RPC. Must match a branch of
    /// `firewall_template_commands()` in hyperion-core/src/service.rs
    /// — except for templates marked `applyable=false`, which still
    /// only show the snippet (e.g. worker_rpc needs <MASTER_IP>
    /// substitution we don't have at apply-time).
    pub apply_id: &'static str,
    /// `false` ⇒ no Apply button, snippet-only. Keeps the worker_rpc
    /// template visible without offering a non-functional Apply.
    pub applyable: bool,
}

/// Hardcoded "open these together" port sets. Listed in the order
/// most operators reach for them: web first (every site needs it),
/// then mail (only sites that handle email), then hyperion (only
/// the master), then SSH lockdown patterns.
fn port_templates() -> Vec<PortTemplate> {
    vec![
        PortTemplate {
            name: "Web (HTTP + HTTPS)",
            apply_id: "web",
            applyable: true,
            ports_summary: "80/tcp, 443/tcp+udp",
            description: "What nginx needs to serve every hosting. \
                          UDP/443 covers HTTP/3 (QUIC); skip it if you don't \
                          run HTTP/3.",
            snippet: "# Apply via SSH on the target node:\n\
                      sudo nft -c 'add table inet hyperion { }'\n\
                      sudo nft -c 'add chain inet hyperion input { type filter hook input priority 0 \\; policy accept \\; }'\n\
                      sudo nft add rule inet hyperion input tcp dport { 80, 443 } accept comment \\\"web\\\"\n\
                      sudo nft add rule inet hyperion input udp dport 443 accept comment \\\"http3-quic\\\"\n\
                      sudo nft list ruleset > /etc/nftables.conf",
        },
        PortTemplate {
            name: "Mail (SMTP + IMAP + POP3 + submission)",
            apply_id: "mail",
            applyable: true,
            ports_summary: "25, 110, 143, 465, 587, 993, 995 / tcp",
            description: "Open postfix + dovecot. 25 is mandatory for any \
                          mail-receiving box; 465+587 for submission; \
                          993+995 are IMAPS/POP3S for clients. Skip 110/143 \
                          (cleartext) on production setups.",
            snippet: "# Apply via SSH:\n\
                      sudo nft -c 'add table inet hyperion { }'\n\
                      sudo nft -c 'add chain inet hyperion input { type filter hook input priority 0 \\; policy accept \\; }'\n\
                      sudo nft add rule inet hyperion input tcp dport { 25, 465, 587, 993, 995 } accept comment \\\"mail-secure\\\"\n\
                      sudo nft list ruleset > /etc/nftables.conf\n\
                      # Add cleartext if you really need them:\n\
                      # sudo nft add rule inet hyperion input tcp dport { 110, 143 } accept comment \\\"mail-cleartext\\\"",
        },
        PortTemplate {
            name: "Hyperion (panel + master RPC)",
            apply_id: "hyperion",
            applyable: true,
            ports_summary: "8443, 9443 / tcp",
            description: "Open ONLY on the master node. 8443 is the panel \
                          (operator web UI); 9443 is the master↔worker RPC. \
                          On workers, 9443 should be open to the master's \
                          IP only — see the next template.",
            snippet: "# Master node — both ports open to the world:\n\
                      sudo nft -c 'add table inet hyperion { }'\n\
                      sudo nft -c 'add chain inet hyperion input { type filter hook input priority 0 \\; policy accept \\; }'\n\
                      sudo nft add rule inet hyperion input tcp dport { 8443, 9443 } accept comment \\\"hyperion\\\"\n\
                      sudo nft list ruleset > /etc/nftables.conf",
        },
        PortTemplate {
            name: "Worker RPC (master-only access)",
            apply_id: "worker_rpc",
            // No Apply — the rule needs <MASTER_IP> substitution that
            // we don't have at apply-time without an extra arg.
            // Operator copies the snippet, substitutes, runs by hand.
            applyable: false,
            ports_summary: "9443 / tcp, source-restricted",
            description: "On a worker node, restrict 9443 to the master's \
                          public IP. Replace <MASTER_IP> with your master's \
                          IP. Everyone else gets dropped — the public-facing \
                          surface is just nginx (80/443).",
            snippet: "# Replace <MASTER_IP> with your master node's public IP:\n\
                      sudo nft -c 'add table inet hyperion { }'\n\
                      sudo nft -c 'add chain inet hyperion input { type filter hook input priority 0 \\; policy accept \\; }'\n\
                      sudo nft add rule inet hyperion input ip saddr <MASTER_IP> tcp dport 9443 accept comment \\\"hyperion-rpc-from-master\\\"\n\
                      sudo nft list ruleset > /etc/nftables.conf",
        },
        PortTemplate {
            name: "SSH (open)",
            apply_id: "ssh",
            applyable: true,
            ports_summary: "22 / tcp",
            description: "Standard SSH — open to the world. Pair with \
                          fail2ban or sshd's PermitRootLogin no + key-only \
                          auth.",
            snippet: "sudo nft -c 'add table inet hyperion { }'\n\
                      sudo nft -c 'add chain inet hyperion input { type filter hook input priority 0 \\; policy accept \\; }'\n\
                      sudo nft add rule inet hyperion input tcp dport 22 accept comment \\\"ssh\\\"\n\
                      sudo nft list ruleset > /etc/nftables.conf",
        },
        PortTemplate {
            name: "FTP (vsftpd, passive)",
            apply_id: "ftp",
            applyable: true,
            ports_summary: "21/tcp + 40000-50000/tcp",
            description: "Open vsftpd's control port + the passive data \
                          port range (configured in vsftpd.conf as \
                          pasv_min_port / pasv_max_port). Keep the data \
                          range tight to avoid leaving 30k ports open if \
                          you can.",
            snippet: "sudo nft -c 'add table inet hyperion { }'\n\
                      sudo nft -c 'add chain inet hyperion input { type filter hook input priority 0 \\; policy accept \\; }'\n\
                      sudo nft add rule inet hyperion input tcp dport 21 accept comment \\\"ftp-control\\\"\n\
                      sudo nft add rule inet hyperion input tcp dport 40000-50000 accept comment \\\"ftp-passive\\\"\n\
                      sudo nft list ruleset > /etc/nftables.conf",
        },
    ]
}

pub async fn get_firewall(
    State(state): State<SharedState>,
    ctx: AuthCtx,
) -> Result<Response, AppError> {
    // Only admins should see the ruleset — it reveals service
    // topology that an operator role doesn't need.
    if !ctx.can(Capability::SecurityManage) {
        return Ok(
            Redirect::to("/?flash_error=admin+role+required+to+view+firewall").into_response(),
        );
    }
    let mut nodes: Vec<NodeFirewall> = Vec::new();
    // Master — firewall ruleset + active bans from the local agent.
    {
        let (view, unreachable) =
            match hyperion_rpc_client::call(&state.agent_socket, Request::FirewallList).await {
                Ok(RpcResponse::FirewallList(v)) => (v, false),
                _ => (hyperion_types::FirewallView::default(), true),
            };
        let bans = match hyperion_rpc_client::call(
            &state.agent_socket,
            Request::BanList { hosting_id: None },
        )
        .await
        {
            Ok(RpcResponse::BanList(b)) => b,
            _ => Vec::new(),
        };
        let (ban_total, ban_auto, ban_manual, ban_v4, ban_v6, recent_bans) = summarize_bans(bans);
        nodes.push(NodeFirewall {
            node_id: "master".to_string(),
            label: "master".to_string(),
            view,
            unreachable,
            drained: false,
            drain_reason: String::new(),
            ban_total,
            ban_auto,
            ban_manual,
            ban_v4,
            ban_v6,
            recent_bans,
        });
    }
    // Workers — fan out firewall + bans via dispatcher.
    if let Ok(RpcResponse::NodesList(workers)) =
        hyperion_rpc_client::call(&state.agent_socket, Request::NodesList).await
    {
        for w in workers {
            let view = match crate::dispatcher::dispatch_to_node(
                &state,
                Some(w.node_id.as_str()),
                Request::FirewallList,
            )
            .await
            {
                Ok(RpcResponse::FirewallList(v)) => Some(v),
                _ => None,
            };
            let unreachable = view.is_none();
            let bans = match crate::dispatcher::dispatch_to_node(
                &state,
                Some(w.node_id.as_str()),
                Request::BanList { hosting_id: None },
            )
            .await
            {
                Ok(RpcResponse::BanList(b)) => b,
                _ => Vec::new(),
            };
            let (ban_total, ban_auto, ban_manual, ban_v4, ban_v6, recent_bans) =
                summarize_bans(bans);
            nodes.push(NodeFirewall {
                node_id: w.node_id.clone(),
                label: w.label.clone(),
                view: view.unwrap_or_default(),
                unreachable,
                drained: w.is_drained,
                drain_reason: w.drain_reason.clone(),
                ban_total,
                ban_auto,
                ban_manual,
                ban_v4,
                ban_v6,
                recent_bans,
            });
        }
    }
    // Cluster posture roll-up for the top-of-page summary.
    let summary = FwSummary {
        nodes_total: nodes.len(),
        nodes_reachable: nodes.iter().filter(|n| !n.unreachable).count(),
        ban_total: nodes.iter().map(|n| n.ban_total).sum(),
        ban_auto: nodes.iter().map(|n| n.ban_auto).sum(),
        ban_manual: nodes.iter().map(|n| n.ban_manual).sum(),
        open_ports_total: nodes.iter().map(|n| n.view.ports.len()).sum(),
    };
    // Apply-target list mirrors `nodes` but with each entry tagged
    // by reachability so the template can grey-out Apply buttons on
    // unreachable nodes. "master" is a sentinel; the post_apply
    // handler maps it to the local agent socket.
    let apply_targets: Vec<ApplyTarget> = nodes
        .iter()
        .map(|n| ApplyTarget {
            node_id: n.node_id.clone(),
            label: n.label.clone(),
            applyable: !n.unreachable,
        })
        .collect();
    let tpl = FirewallTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "firewall",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        nodes,
        templates: port_templates(),
        apply_targets,
        summary,
        csrf_token: super::session_csrf_token(&state, &ctx),
    };
    Ok(Html(tpl.render()?).into_response())
}

#[derive(Deserialize)]
pub struct ApplyTemplateForm {
    pub template_id: String,
    /// "master" (sentinel) or a worker node_id. Dispatcher's
    /// LOCAL_NODE_SENTINEL covers the local-socket path.
    pub target_node: String,
    pub _csrf: String,
}

/// POST /firewall/apply — runs the requested template on the
/// requested node. Returns a small inline HTML fragment so the
/// /firewall page can swap it next to the Apply button via HTMX.
///
/// We don't redirect on success — the page would lose the
/// expanded snippet pane the operator likely had open. The
/// fragment carries the result inline + a hint to refresh the
/// per-node port table at the top if they want to see the new
/// rules light up.
pub async fn post_apply(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<ApplyTemplateForm>,
) -> Result<Response, AppError> {
    if !ctx.can(Capability::SecurityManage) {
        return Ok((
            axum::http::StatusCode::FORBIDDEN,
            [("content-type", "text/html; charset=utf-8")],
            "<span class=\"pill err\">admin role required</span>",
        )
            .into_response());
    }
    let target = if form.target_node.trim() == "master"
        || form.target_node.trim().is_empty()
        || form.target_node == crate::dispatcher::LOCAL_NODE_SENTINEL
    {
        None
    } else {
        Some(form.target_node.as_str())
    };
    let resp = crate::dispatcher::dispatch_to_node(
        &state,
        target,
        Request::FirewallApplyTemplate {
            template_id: form.template_id.clone(),
        },
    )
    .await?;
    let body = match resp {
        RpcResponse::FirewallTemplateApplied {
            applied: true, ..
        } => format!(
            "<span class=\"pill ok\" title=\"Rules added to inet hyperion table + persisted to /etc/nftables.conf\">✓ applied on {}</span>",
            html_escape(&form.target_node)
        ),
        RpcResponse::FirewallTemplateApplied {
            applied: false,
            error,
            ..
        } => format!(
            "<span class=\"pill err\" title=\"{}\">✗ failed</span>",
            html_escape(&error)
        ),
        RpcResponse::Error(e) => format!(
            "<span class=\"pill err\" title=\"{}\">✗ RPC error</span>",
            html_escape(&e.to_string())
        ),
        _ => "<span class=\"pill err\">✗ unexpected response</span>".to_string(),
    };
    Ok(([("content-type", "text/html; charset=utf-8")], body).into_response())
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
