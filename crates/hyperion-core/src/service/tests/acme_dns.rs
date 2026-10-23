//! Tests for `service::acme_dns`.

use super::*;

async fn bare() -> HostingService<MockAdapterPort> {
    svc(
        open_memory().await.expect("memory db"),
        MockAdapterPort::new(),
    )
}

/// A firewall step that succeeds (`ok`) or fails like nft does.
fn fw(
    ok: bool,
) -> impl FnOnce(bool) -> std::future::Ready<Result<(bool, String, String), RpcError>> {
    move |_| {
        std::future::ready(Ok(if ok {
            (true, "1 rule(s) added".into(), String::new())
        } else {
            (false, String::new(), "nft: Operation not permitted".into())
        }))
    }
}

const NAMED: &str = "UNCONN 0 0 203.0.113.5:53 0.0.0.0:* users:((\"named\",pid=1,fd=5))\n";

#[tokio::test]
async fn enable_refuses_when_port_53_is_taken() {
    let s = bare().await;
    let err = s
        .acme_dns_config_save(
            Some("acme.panel.example".into()),
            "ns-acme.panel.example".into(),
            Some("203.0.113.5".into()),
            None,
            true,
            NAMED,
            fw(true),
        )
        .await
        .expect_err("port 53 is held by named");
    assert!(err.to_string().contains("named"), "{err}");
    let cfg = s.acme_dns_config_get().await.expect("get");
    assert!(!cfg.enabled);
    assert_eq!(cfg.zone.as_deref(), Some("acme.panel.example"));
    assert_eq!(cfg.check_token.len(), 32);
}

#[tokio::test]
async fn enable_rejects_ns_host_inside_zone() {
    let s = bare().await;
    for ns in ["ns.acme.panel.example", "acme.panel.example"] {
        let err = s
            .acme_dns_config_save(
                Some("acme.panel.example".into()),
                ns.into(),
                None,
                None,
                true,
                "",
                fw(true),
            )
            .await
            .expect_err("ns inside the zone");
        assert!(matches!(err, RpcError::Validation { .. }), "{err}");
    }
    assert!(s
        .acme_dns_config_get()
        .await
        .expect("get")
        .check_token
        .is_empty());
}

#[tokio::test]
async fn check_token_is_generated_once() {
    let s = bare().await;
    let a = s
        .acme_dns_config_save(None, String::new(), None, None, false, "", fw(true))
        .await
        .expect("save");
    let b = s
        .acme_dns_config_save(
            Some("acme.panel.example".into()),
            "ns-acme.panel.example".into(),
            None,
            None,
            false,
            "",
            fw(true),
        )
        .await
        .expect("save");
    assert_eq!(a.check_token.len(), 32);
    assert_eq!(a.check_token, b.check_token);
}

async fn save(
    s: &HostingService<MockAdapterPort>,
    enabled: bool,
    firewall_ok: bool,
) -> Result<hyperion_types::AcmeDnsConfig, RpcError> {
    s.acme_dns_config_save(
        Some("acme.panel.example".into()),
        "ns-acme.panel.example".into(),
        None,
        None,
        enabled,
        "",
        fw(firewall_ok),
    )
    .await
}

#[tokio::test]
async fn enable_succeeds_once_the_firewall_is_open() {
    let s = bare().await;
    assert!(save(&s, true, true).await.expect("enable").enabled);
    assert!(s.acme_dns_config_get().await.expect("get").enabled);
}

#[tokio::test]
async fn enable_fails_closed_when_the_firewall_preset_fails() {
    let s = bare().await;
    let err = save(&s, true, false).await.expect_err("nft failed");
    assert!(err.to_string().contains("Operation not permitted"), "{err}");
    assert!(!s.acme_dns_config_get().await.expect("get").enabled);
}

#[tokio::test]
async fn disable_reports_a_failed_firewall_removal() {
    let s = bare().await;
    save(&s, true, true).await.expect("enable");
    let err = save(&s, false, false).await.expect_err("nft failed");
    let msg = err.to_string();
    assert!(msg.contains("may still be open"), "{msg}");
    assert!(msg.contains("Operation not permitted"), "{msg}");
    assert!(
        !s.acme_dns_config_get().await.expect("get").enabled,
        "the responder is off even though the port could not be closed"
    );
}

#[test]
fn port_53_holders_skip_loopback_and_the_agent() {
    let ss = "UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:* users:((\"systemd-resolve\",pid=9,fd=13))\n\
              UNCONN 0 0 127.0.0.54:53 0.0.0.0:* users:((\"systemd-resolve\",pid=9,fd=15))\n\
              LISTEN 0 4096 [::1]:53 [::]:* users:((\"unbound\",pid=3,fd=4))\n\
              UNCONN 0 0 [fe80::1]%eth0:53 [::]:* users:((\"dnsmasq\",pid=4,fd=4))\n\
              UNCONN 0 0 203.0.113.5:53 0.0.0.0:* users:((\"hyperion-agent\",pid=2,fd=30))\n\
              UNCONN 0 0 0.0.0.0:5353 0.0.0.0:* users:((\"avahi-daemon\",pid=5,fd=12))\n";
    assert!(port_53_holders_from_ss(ss).is_empty());
    let ss = "LISTEN 0 10 *:53 *:* users:((\"pdns_server\",pid=7,fd=6))\n\
              UNCONN 0 0 [::]:53 [::]:*\n";
    assert_eq!(
        port_53_holders_from_ss(ss),
        vec![
            "pdns_server on *:53".to_string(),
            "an unknown process on [::]:53".to_string()
        ]
    );
}

#[test]
fn acme_dns_firewall_template_has_udp_and_tcp_53() {
    let cmds = firewall_template_commands("acme-dns").expect("known preset");
    let joined: Vec<String> = cmds.iter().map(|c| c[5..].join(" ")).collect();
    assert_eq!(
        joined,
        vec![
            "udp dport 53 accept comment \"hyperion:acme-dns\"",
            "tcp dport 53 accept comment \"hyperion:acme-dns-tcp\"",
        ]
    );
    assert_eq!(
        firewall_template_tags("acme-dns").expect("tags"),
        vec!["acme-dns", "acme-dns-tcp"]
    );
    assert!(FIREWALL_TEMPLATE_IDS.contains(&"acme-dns"));
}

#[tokio::test]
async fn renew_report_failure_raises_auto_failed_alert() {
    use hyperion_state::web_users::WebRole;
    let pool = open_memory().await.expect("open");
    let s = svc(pool, happy_mocks());
    let me = seed_web_user(&s, "boss", WebRole::Admin).await;
    s.acme_dns_renew_report(
        "base.cz".into(),
        "n1".into(),
        true,
        "renewed".into(),
        20,
        true,
    )
    .await
    .expect("ok report");
    assert!(manual_kinds(&s, me).await.is_empty(), "success is silent");
    s.acme_dns_renew_report(
        "base.cz".into(),
        "n1".into(),
        false,
        "txt mismatch".into(),
        9,
        true,
    )
    .await
    .expect("failed report");
    let feed = s.notifications_feed(me, 10).await.expect("feed");
    assert_eq!(feed.items.len(), 1);
    assert_eq!(feed.items[0].kind, "cert.wildcard_auto_failed:base.cz");
    assert_eq!(feed.items[0].severity, "warn");
    assert!(feed.items[0].body.contains("txt mismatch"));
    // A hosting's wildcard links to the hosting, not the preview page.
    assert_eq!(feed.items[0].href, "/hostings/base.cz");
    s.acme_dns_renew_report(
        "preview.cz".into(),
        "n1".into(),
        false,
        "x".into(),
        0,
        false,
    )
    .await
    .expect("expired report");
    let feed = s.notifications_feed(me, 10).await.expect("feed");
    let preview = feed
        .items
        .iter()
        .find(|n| n.kind == "cert.wildcard_auto_failed:preview.cz")
        .expect("preview alert");
    assert_eq!(preview.severity, "error");
    assert_eq!(preview.href, "/settings/https#preview-wildcard");
}

#[tokio::test]
async fn zone_broken_raises_one_alert_kind() {
    use hyperion_state::web_users::WebRole;
    let pool = open_memory().await.expect("open");
    let s = svc(pool, happy_mocks());
    let me = seed_web_user(&s, "boss", WebRole::Admin).await;
    s.acme_dns_zone_broken("NS does not resolve".into())
        .await
        .expect("report");
    assert_eq!(manual_kinds(&s, me).await, ["acme_dns.zone_broken"]);
}

#[tokio::test]
async fn label_and_value_rpcs_drive_the_state_tables() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool, happy_mocks());
    let base = Domain::parse("example.cz").expect("domain");
    let l = s
        .acme_dns_label_ensure(base.clone(), Some("h1".into()))
        .await
        .expect("ensure");
    assert_eq!(
        s.acme_dns_labels().await.expect("all"),
        std::slice::from_ref(&l)
    );
    s.acme_dns_label_mark(base.clone(), true, None)
        .await
        .expect("mark");
    assert!(s.acme_dns_labels().await.expect("all")[0]
        .verified_at
        .is_some());
    let before = now_secs();
    s.acme_dns_values_set(l.label.clone(), vec!["v".into()])
        .await
        .expect("set");
    let vals = hyperion_state::acme_dns::values_live(&s.pool, before)
        .await
        .expect("values");
    assert_eq!(vals.get(&l.label).map(Vec::len), Some(1));
    s.acme_dns_values_clear(l.label.clone())
        .await
        .expect("clear");
    s.acme_dns_labels_delete_for_hosting("h1".into())
        .await
        .expect("del hosting");
    assert!(s.acme_dns_labels().await.expect("all").is_empty());
    s.acme_dns_label_delete(base).await.expect("delete");
}
