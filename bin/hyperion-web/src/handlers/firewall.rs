//! `/firewall` — every node's firewall, one panel per node.
//!
//! Fans out `FirewallList`, `BanList` and `FirewallArmStatus` to the master
//! and every enrolled worker. Per node the page answers, in this order:
//!
//!   1. is this box actually filtering? (hyperion's chain policy — `accept`
//!      means every rule hyperion adds changes nothing)
//!   2. what is open, to whom, and who opened it
//!   3. which presets are applied — apply or remove them here
//!   4. who is banned right now
//!
//! The policy is read from the raw ruleset rather than a new RPC field, so a
//! node running an older agent still reports it.

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
    /// Every preset, for the "commands" reference at the bottom.
    templates: Vec<PortTemplate>,
    summary: FwSummary,
    csrf_token: String,
}

/// One recent ban shown inline on a node panel.
pub struct BanLine {
    pub ip: String,
    pub reason: String,
    pub source: String,
}

/// Cluster-wide headline numbers.
pub struct FwSummary {
    pub nodes_total: usize,
    pub nodes_reachable: usize,
    /// Nodes whose hyperion chain drops by default (confirmed or not).
    pub nodes_filtering: usize,
    pub ban_total: usize,
    pub ban_auto: usize,
    pub ban_manual: usize,
}

/// A preset as it stands on one node.
pub struct NodePreset {
    pub id: &'static str,
    pub name: &'static str,
    pub ports_summary: &'static str,
    pub applied: bool,
}

/// A port opened from the panel's "Open a port" form, read back from its
/// rule tag (`hyperion:custom-<proto>-<port>[-from-<source>]`).
pub struct CustomRule {
    /// The preset id the agent knows it by: `custom:<proto>:<port>[:<source>]`.
    pub id: String,
    pub label: String,
}

/// Every custom rule in a raw ruleset. Mirrors `CustomPort::from_tag` in
/// hyperion-core; the agent re-validates whatever id comes back.
fn custom_rules(raw: &str) -> Vec<CustomRule> {
    let mut out: Vec<CustomRule> = Vec::new();
    for chunk in raw.split("comment \"hyperion:custom-").skip(1) {
        let Some(end) = chunk.find('"') else { continue };
        let tag = &chunk[..end];
        let Some((proto, rest)) = tag.split_once('-') else {
            continue;
        };
        let (port, source) = match rest.split_once("-from-") {
            Some((p, s)) => (p, Some(s)),
            None => (rest, None),
        };
        let (id, label) = match source {
            Some(s) => (
                format!("custom:{proto}:{port}:{s}"),
                format!("{port} {proto} from {s}"),
            ),
            None => (format!("custom:{proto}:{port}"), format!("{port} {proto}")),
        };
        if !out.iter().any(|c| c.id == id) {
            out.push(CustomRule { id, label });
        }
    }
    out
}

pub struct NodeFirewall {
    pub node_id: String,
    pub label: String,
    pub view: hyperion_types::FirewallView,
    /// True when the RPC failed entirely — render a "node
    /// unreachable" notice instead of an empty panel.
    pub unreachable: bool,
    /// Drained nodes are intentionally quiet, not broken.
    pub drained: bool,
    pub drain_reason: String,
    /// `"accept"`, `"drop"`, or empty when hyperion's chain does not exist.
    pub policy: String,
    /// Input-hook chains of OTHER firewalls on the box (ufw, firewalld, a
    /// hand-written ruleset), e.g. `ip filter / INPUT · policy drop`. A port
    /// has to be allowed by every one of them, not just hyperion's.
    pub other_chains: Vec<String>,
    pub presets: Vec<NodePreset>,
    /// Ports opened from the panel outside the presets.
    pub custom: Vec<CustomRule>,
    /// Active nftables bans on this node (from BanList).
    pub ban_total: usize,
    pub ban_auto: usize,
    pub ban_manual: usize,
    pub ban_v4: usize,
    pub ban_v6: usize,
    /// Newest few bans, for an at-a-glance "who's being dropped".
    pub recent_bans: Vec<BanLine>,
    /// Seconds left to confirm a default-drop switch before it reverts on its
    /// own. `None` when nothing is waiting — which is the normal state.
    pub armed_seconds_left: Option<i64>,
}

impl NodeFirewall {
    pub fn open_to_world(&self) -> usize {
        self.view
            .ports
            .iter()
            .filter(|p| !p.source_restricted)
            .count()
    }
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
        })
        .collect();
    (total, auto, total - auto, total - v6, v6, recent)
}

pub struct PortTemplate {
    pub name: &'static str,
    pub ports_summary: &'static str,
    pub description: &'static str,
    pub snippet: &'static str,
    /// Id sent to the agent. Must match `firewall_template_commands()` in
    /// hyperion-core/src/service.rs, except for snippet-only presets.
    pub apply_id: &'static str,
    /// `false` ⇒ snippet only (worker_rpc needs the master's IP).
    pub applyable: bool,
    /// The `hyperion:<tag>` comments its rules carry — the preset counts as
    /// applied on a node when all of them are in the ruleset. Same lock-step
    /// as `apply_id`.
    pub tags: &'static [&'static str],
}

/// Common header of every snippet: create hyperion's table and chain if they
/// are missing. No `policy` on purpose — on an existing chain that would SET
/// it, and switch a default-drop node back to accepting everything. (The
/// snippets used `nft -c` here, which only checks syntax, so the table was
/// never created and the next line failed.)
macro_rules! snippet_header {
    () => {
        "sudo nft add table inet hyperion\n\
         sudo nft add chain inet hyperion input '{ type filter hook input priority 0 ; }'\n"
    };
}

fn port_templates() -> Vec<PortTemplate> {
    vec![
        PortTemplate {
            name: "Web",
            apply_id: "web",
            applyable: true,
            tags: &["web", "web-quic"],
            ports_summary: "80, 443 tcp · 443 udp",
            description: "What nginx needs to serve every site. UDP 443 is HTTP/3.",
            snippet: concat!(
                snippet_header!(),
                "sudo nft add rule inet hyperion input tcp dport '{ 80, 443 }' accept comment '\"hyperion:web\"'\n",
                "sudo nft add rule inet hyperion input udp dport 443 accept comment '\"hyperion:web-quic\"'"
            ),
        },
        PortTemplate {
            name: "Mail",
            apply_id: "mail",
            applyable: true,
            tags: &["mail"],
            ports_summary: "25, 465, 587, 993, 995 tcp",
            description: "SMTP, submission, IMAPS and POP3S. Cleartext IMAP/POP3 \
                          (143/110) are left closed.",
            snippet: concat!(
                snippet_header!(),
                "sudo nft add rule inet hyperion input tcp dport '{ 25, 465, 587, 993, 995 }' accept comment '\"hyperion:mail\"'"
            ),
        },
        PortTemplate {
            name: "Hyperion panel + RPC",
            apply_id: "hyperion",
            applyable: true,
            tags: &["hyperion"],
            ports_summary: "8443, 8447, 9443 tcp",
            description: "Panel, phpMyAdmin (8447) and master↔node RPC, open to everyone. Default-drop \
                          already keeps the ports the panel listens on, so this is \
                          only needed when another firewall drops them.",
            snippet: concat!(
                snippet_header!(),
                "sudo nft add rule inet hyperion input tcp dport '{ 8443, 8447, 9443 }' accept comment '\"hyperion:hyperion\"'"
            ),
        },
        PortTemplate {
            name: "SSH",
            apply_id: "ssh",
            applyable: true,
            tags: &["ssh"],
            ports_summary: "22 tcp",
            description: "Port 22 open to everyone. Default-drop already keeps \
                          every port sshd listens on.",
            snippet: concat!(
                snippet_header!(),
                "sudo nft add rule inet hyperion input tcp dport 22 accept comment '\"hyperion:ssh\"'"
            ),
        },
        PortTemplate {
            name: "FTP",
            apply_id: "ftp",
            applyable: true,
            tags: &["ftp-control", "ftp-passive"],
            ports_summary: "21 + 40000–50000 tcp",
            description: "vsftpd control port (the configured one, if not 21) and \
                          the passive data range. Both are needed — the control \
                          port alone hangs on the first listing.",
            snippet: concat!(
                snippet_header!(),
                "sudo nft add rule inet hyperion input tcp dport 21 accept comment '\"hyperion:ftp-control\"'\n",
                "sudo nft add rule inet hyperion input tcp dport 40000-50000 accept comment '\"hyperion:ftp-passive\"'"
            ),
        },
        PortTemplate {
            name: "Worker RPC from the master only",
            apply_id: "worker_rpc",
            applyable: false,
            tags: &[],
            ports_summary: "9443 tcp, one source",
            description: "On a worker, admit the RPC port from the master's IP \
                          only. Replace <MASTER_IP> first.",
            snippet: concat!(
                snippet_header!(),
                "sudo nft add rule inet hyperion input ip saddr <MASTER_IP> tcp dport 9443 accept comment '\"hyperion-rpc-from-master\"'"
            ),
        },
    ]
}

/// What a node's raw ruleset says about its input filtering: hyperion's own
/// chain policy, and every OTHER base chain on the input hook.
///
/// Only nft output is understood; for iptables the policy is unknown.
fn input_chains(raw: &str) -> (String, Vec<String>) {
    let mut policy = String::new();
    let mut others = Vec::new();
    let mut table = String::new();
    let mut chain = String::new();
    for line in raw.lines() {
        let l = line.trim();
        if let Some(rest) = l.strip_prefix("table ") {
            table = rest.trim_end_matches('{').trim().to_string();
        } else if let Some(rest) = l.strip_prefix("chain ") {
            chain = rest
                .split(|c: char| c == '{' || c.is_whitespace())
                .next()
                .unwrap_or("")
                .to_string();
        } else if l.contains("hook input") {
            let p = l
                .split_once("policy ")
                .map(|(_, r)| r.trim_end_matches(';').trim().to_string())
                .unwrap_or_else(|| "accept".to_string());
            if table == "inet hyperion" && chain == "input" {
                policy = p;
            } else {
                others.push(format!("{table} / {chain} · policy {p}"));
            }
        }
    }
    (policy, others)
}

fn node_presets(raw: &str) -> Vec<NodePreset> {
    port_templates()
        .into_iter()
        .filter(|t| t.applyable)
        .map(|t| NodePreset {
            id: t.apply_id,
            name: t.name,
            ports_summary: t.ports_summary,
            applied: t
                .tags
                .iter()
                .all(|tag| raw.contains(&format!("comment \"hyperion:{tag}\""))),
        })
        .collect()
}

/// Query one node (`None` = the master's local agent).
async fn load_node(
    state: &SharedState,
    target: Option<&str>,
) -> (
    Option<hyperion_types::FirewallView>,
    Vec<hyperion_types::IpBanWire>,
    Option<i64>,
) {
    let view = match crate::dispatcher::dispatch_to_node(state, target, Request::FirewallList).await
    {
        Ok(RpcResponse::FirewallList(v)) => Some(v),
        _ => None,
    };
    let bans = match crate::dispatcher::dispatch_to_node(
        state,
        target,
        Request::BanList { hosting_id: None },
    )
    .await
    {
        Ok(RpcResponse::BanList(b)) => b,
        _ => Vec::new(),
    };
    let armed = match crate::dispatcher::dispatch_to_node(state, target, Request::FirewallArmStatus)
        .await
    {
        Ok(RpcResponse::FirewallDefaultDrop {
            armed_seconds_left, ..
        }) => armed_seconds_left,
        _ => None,
    };
    (view, bans, armed)
}

fn build_node(
    node_id: String,
    label: String,
    loaded: (
        Option<hyperion_types::FirewallView>,
        Vec<hyperion_types::IpBanWire>,
        Option<i64>,
    ),
    drained: bool,
    drain_reason: String,
) -> NodeFirewall {
    let (view, bans, armed_seconds_left) = loaded;
    let unreachable = view.is_none();
    let view = view.unwrap_or_default();
    let (policy, other_chains) = if view.backend == "nft" {
        input_chains(&view.raw)
    } else {
        (String::new(), Vec::new())
    };
    let presets = node_presets(&view.raw);
    let custom = custom_rules(&view.raw);
    let (ban_total, ban_auto, ban_manual, ban_v4, ban_v6, recent_bans) = summarize_bans(bans);
    NodeFirewall {
        node_id,
        label,
        view,
        unreachable,
        drained,
        drain_reason,
        policy,
        other_chains,
        presets,
        custom,
        ban_total,
        ban_auto,
        ban_manual,
        ban_v4,
        ban_v6,
        recent_bans,
        armed_seconds_left,
    }
}

fn allowed(ctx: &AuthCtx) -> bool {
    ctx.can(Capability::SecurityManage) && ctx.scope_all()
}

pub async fn get_firewall(
    State(state): State<SharedState>,
    ctx: AuthCtx,
) -> Result<Response, AppError> {
    // Only admins should see the ruleset — it reveals service
    // topology that an operator role doesn't need.
    if !allowed(&ctx) {
        return Ok(
            Redirect::to("/?flash_error=admin+role+required+to+view+firewall").into_response(),
        );
    }
    let mut nodes: Vec<NodeFirewall> = vec![build_node(
        "master".to_string(),
        "master".to_string(),
        load_node(&state, None).await,
        false,
        String::new(),
    )];
    if let Ok(RpcResponse::NodesList(workers)) =
        hyperion_rpc_client::call(&state.agent_socket, Request::NodesList).await
    {
        for w in workers {
            let loaded = load_node(&state, Some(w.node_id.as_str())).await;
            nodes.push(build_node(
                w.node_id.clone(),
                w.label.clone(),
                loaded,
                w.is_drained,
                w.drain_reason.clone(),
            ));
        }
    }
    let summary = FwSummary {
        nodes_total: nodes.len(),
        nodes_reachable: nodes.iter().filter(|n| !n.unreachable).count(),
        nodes_filtering: nodes.iter().filter(|n| n.policy == "drop").count(),
        ban_total: nodes.iter().map(|n| n.ban_total).sum(),
        ban_auto: nodes.iter().map(|n| n.ban_auto).sum(),
        ban_manual: nodes.iter().map(|n| n.ban_manual).sum(),
    };
    let tpl = FirewallTpl {
        username: &ctx.username,
        user_initial: super::user_initial(&ctx.username),
        active: "firewall",
        css_version: super::css_version(),
        htmx_version: super::htmx_version(),
        nodes,
        templates: port_templates(),
        summary,
        csrf_token: super::session_csrf_token(&state, &ctx),
    };
    Ok(Html(tpl.render()?).into_response())
}

/// `"master"` / empty / the local sentinel ⇒ the local agent.
fn target_of(node: &str) -> Option<&str> {
    let n = node.trim();
    if n == "master" || n.is_empty() || n == crate::dispatcher::LOCAL_NODE_SENTINEL {
        None
    } else {
        Some(n)
    }
}

/// Back to the page, at the node's panel, with a toast.
fn back(node: &str, ok: Result<String, String>) -> Response {
    let (key, msg) = match ok {
        Ok(m) => ("flash", m),
        Err(e) => ("flash_error", e),
    };
    let anchor: String = node
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    Redirect::to(&format!(
        "/firewall?{key}={}#node-{anchor}",
        crate::handlers::hostings::urlencoding(&msg)
    ))
    .into_response()
}

#[derive(Deserialize)]
pub struct DefaultDropForm {
    pub target_node: String,
    /// "enable" | "confirm" | "disable"
    pub action: String,
}

/// POST /firewall/default-drop — switch a node's chain to `policy drop`,
/// confirm that the operator still has access, or switch it back.
///
/// Three actions behind one route because they are one conversation: turning
/// it on ARMS a deadline, and the only two ways out are confirming or letting
/// it expire.
pub async fn post_default_drop(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<DefaultDropForm>,
) -> Result<Response, AppError> {
    // This can take the node off the network, so it is admin-only and never
    // available to a tenant role.
    if !allowed(&ctx) {
        return Ok(back(&form.target_node, Err("admin role required".into())));
    }
    let req = match form.action.as_str() {
        // Five minutes: long enough to open a second terminal and try, short
        // enough that a locked-out operator is not staring at a dead box.
        "enable" => Request::FirewallEnableDefaultDrop {
            rollback_after_secs: 300,
        },
        "confirm" => Request::FirewallConfirmDefaultDrop,
        "disable" => Request::FirewallDisableDefaultDrop,
        other => {
            return Ok(back(
                &form.target_node,
                Err(format!("unknown action: {other}")),
            ))
        }
    };
    // Errors used to go to `?error=`, which nothing reads — a refused switch
    // looked exactly like a page reload.
    let res = match crate::dispatcher::dispatch_to_node(&state, target_of(&form.target_node), req)
        .await
    {
        Ok(RpcResponse::FirewallDefaultDrop { message, .. }) => Ok(message),
        Ok(RpcResponse::Error(e)) => Err(e.to_string()),
        Ok(_) => Err("unexpected response from the node".into()),
        Err(e) => Err(e.to_string()),
    };
    Ok(back(&form.target_node, res))
}

#[derive(Deserialize)]
pub struct PresetForm {
    /// A preset id, or `custom:…` to remove a custom port, or empty with
    /// `port`/`proto`/`source` to open one.
    #[serde(default)]
    pub template_id: String,
    #[serde(default)]
    pub port: String,
    #[serde(default)]
    pub proto: String,
    #[serde(default)]
    pub source: String,
    /// "master" (sentinel) or a worker node_id.
    pub target_node: String,
    /// "apply" (default) | "remove"
    #[serde(default)]
    pub action: String,
}

/// POST /firewall/apply — apply or remove a preset on one node, then back to
/// the page so the panel shows the new state.
pub async fn post_apply(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<PresetForm>,
) -> Result<Response, AppError> {
    if !allowed(&ctx) {
        return Ok(back(&form.target_node, Err("admin role required".into())));
    }
    // (id sent to the agent, name for the message)
    let (id, name) = if form.template_id.is_empty() {
        // "Open a port". The agent validates every field again; this only
        // turns an obviously wrong entry into a readable message.
        let port = form.port.trim();
        let proto = form.proto.trim();
        let source = form.source.trim();
        if !matches!(proto, "tcp" | "udp") || !port.parse::<u16>().is_ok_and(|p| p > 0) {
            return Ok(back(
                &form.target_node,
                Err("port must be 1–65535 and protocol tcp or udp".into()),
            ));
        }
        let id = if source.is_empty() {
            format!("custom:{proto}:{port}")
        } else {
            format!("custom:{proto}:{port}:{source}")
        };
        (id, format!("Port {port}/{proto}"))
    } else if form.template_id.starts_with("custom:") {
        (form.template_id.clone(), "Custom port".to_string())
    } else {
        match port_templates()
            .into_iter()
            .find(|t| t.applyable && t.apply_id == form.template_id)
        {
            Some(t) => (t.apply_id.to_string(), t.name.to_string()),
            None => return Ok(back(&form.target_node, Err("unknown preset".into()))),
        }
    };
    let remove = form.action == "remove";
    let req = if remove {
        Request::FirewallRemoveTemplate { template_id: id }
    } else {
        Request::FirewallApplyTemplate { template_id: id }
    };
    let verb = if remove { "removed from" } else { "applied on" };
    let res = match crate::dispatcher::dispatch_to_node(&state, target_of(&form.target_node), req)
        .await
    {
        Ok(RpcResponse::FirewallTemplateApplied {
            applied: true,
            output,
            ..
        }) => Ok(format!("{name} {verb} {} — {output}", form.target_node)),
        Ok(RpcResponse::FirewallTemplateApplied { error, .. }) => Err(format!("{name}: {error}")),
        Ok(RpcResponse::Error(e)) => Err(format!("{name}: {e}")),
        Ok(_) => Err("unexpected response from the node".into()),
        Err(e) => Err(e.to_string()),
    };
    Ok(back(&form.target_node, res))
}

#[cfg(test)]
mod tests {
    use super::*;

    const RAW: &str = "table inet hyperion {\n\tchain input {\n\t\ttype filter hook input priority filter; policy drop;\n\t\ttcp dport { 80, 443 } accept comment \"hyperion:web\"\n\t\tudp dport 443 accept comment \"hyperion:web-quic\"\n\t\ttcp dport 21 accept comment \"hyperion:ftp-control\"\n\t}\n}\ntable ip filter {\n\tchain INPUT {\n\t\ttype filter hook input priority filter; policy drop;\n\t}\n\tchain FORWARD {\n\t\ttype filter hook forward priority filter; policy drop;\n\t}\n}\n";

    #[test]
    fn policy_and_other_firewalls_are_read() {
        let (policy, others) = input_chains(RAW);
        assert_eq!(policy, "drop");
        assert_eq!(others, vec!["ip filter / INPUT · policy drop"]);
        assert_eq!(input_chains("").0, "");
    }

    #[test]
    fn a_preset_is_applied_only_with_all_its_rules() {
        let p = node_presets(RAW);
        let get = |id| p.iter().find(|x| x.id == id).unwrap().applied;
        assert!(get("web"));
        // ftp-control alone: the passive range is missing.
        assert!(!get("ftp"));
        assert!(!get("mail"));
        assert!(!p.iter().any(|x| x.id == "worker_rpc"));
    }

    #[test]
    fn custom_rules_are_listed_with_their_ids() {
        let raw = "tcp dport 8080 accept comment \"hyperion:custom-tcp-8080\"\n\
                   ip saddr 10.0.0.0/8 udp dport 53 accept comment \"hyperion:custom-udp-53-from-10.0.0.0/8\"\n";
        let c = custom_rules(raw);
        assert_eq!(c.len(), 2);
        assert_eq!(c[0].id, "custom:tcp:8080");
        assert_eq!(c[1].id, "custom:udp:53:10.0.0.0/8");
        assert_eq!(c[1].label, "53 udp from 10.0.0.0/8");
    }

    /// Every snippet must actually create the table, and never set a policy
    /// (that would switch default-drop off).
    #[test]
    fn snippets_create_the_table_and_leave_the_policy_alone() {
        for t in port_templates() {
            assert!(!t.snippet.contains("nft -c"), "{}", t.apply_id);
            assert!(t.snippet.contains("nft add table inet hyperion"));
            assert!(!t.snippet.contains("policy"), "{}", t.apply_id);
            for tag in t.tags {
                assert!(
                    t.snippet.contains(&format!("\"hyperion:{tag}\"")),
                    "{} snippet lacks tag {tag}",
                    t.apply_id
                );
            }
        }
    }
}
