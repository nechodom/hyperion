//! Tests that span several domains.

use super::*;

/// The Czech pack must not be reachable by accident: an install that
/// has never touched Settings sends exactly the letter it always did.
#[test]
fn the_english_default_letter_is_unchanged() {
    assert_eq!(
        en().get("care.body"),
        hyperion_types::CARE_REPORT_DEFAULT_BODY_TEMPLATE,
        "the catalogue's English letter drifted from the constant the panel shows"
    );
    assert_eq!(
        en().get("expiry.body"),
        hyperion_types::EXPIRY_WARNING_DEFAULT_BODY_TEMPLATE,
        "the catalogue's English expiry letter drifted from the constant the panel shows"
    );
}

/// The whole point of the key: an absent or unreadable one must resolve
/// to Master. Guessing "standalone" would hide the cluster surface from
/// an operator who has real workers — the failure that actually costs
/// something. Guessing "master" only ever shows a node picker with one
/// entry.
#[tokio::test]
async fn deployment_mode_fails_safe_to_master() {
    let (s, _d) = svc_with_mode(None).await;
    assert_eq!(s.deployment_role(), DeploymentRole::Master);
    assert!(!s.is_standalone());

    // Garbage is not "close enough to standalone" either.
    let (s, _d) = svc_with_mode(Some("stand-alone")).await;
    assert_eq!(s.deployment_role(), DeploymentRole::Master);

    // No config file at all.
    let pool = open_memory().await.expect("memory db");
    let s = svc(pool, MockAdapterPort::new());
    assert_eq!(s.deployment_role(), DeploymentRole::Master);
}

#[tokio::test]
async fn deployment_mode_reads_standalone_and_master() {
    let (s, _d) = svc_with_mode(Some("standalone")).await;
    assert_eq!(s.deployment_role(), DeploymentRole::Standalone);
    assert!(s.is_standalone());

    let (s, _d) = svc_with_mode(Some("master")).await;
    assert_eq!(s.deployment_role(), DeploymentRole::Master);
}

/// An enrollment credential outranks the config key, always. A box that
/// enrolled IS a worker whatever agent.toml claims, so the two can never
/// disagree in a way that matters.
#[tokio::test]
async fn enrollment_credential_outranks_the_mode_key() {
    let dir = tempfile::tempdir().expect("tmp");
    let cfg = dir.path().join("agent.toml");
    std::fs::write(&cfg, "[cluster]\nmode = \"standalone\"\n").expect("write");
    let node_id = dir.path().join("node-id.json");
    std::fs::write(&node_id, "{}").expect("write node-id");
    let pool = open_memory().await.expect("memory db");
    let s = svc(pool, MockAdapterPort::new())
        .with_agent_config_path(cfg)
        .with_node_state_file(node_id);
    assert_eq!(
        s.deployment_role(),
        DeploymentRole::Worker,
        "an enrolled box is a worker even if the config says standalone"
    );
}

#[tokio::test]
async fn is_worker_node_false_when_state_file_missing() {
    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path().join("node-id.json");
    let s = svc_with_state_file(Some(p)).await;
    assert!(!s.is_worker_node(), "path set but file absent → master");
}

#[tokio::test]
async fn is_worker_node_true_when_state_file_exists() {
    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path().join("node-id.json");
    // File present → enrolled worker. hyperion-web absence is
    // expected, not critical.
    tokio::fs::write(&p, b"{}").await.unwrap();
    let s = svc_with_state_file(Some(p)).await;
    assert!(s.is_worker_node());
}

#[test]
fn render_template_substitutes_and_preserves() {
    // Default pass-through.
    assert_eq!(render_template("{message}", &[("message", "hi")]), "hi");
    // Multiple placeholders.
    assert_eq!(
        render_template("[{sev}] {t}", &[("sev", "warn"), ("t", "Disk low")]),
        "[warn] Disk low"
    );
    // Unknown token left verbatim so an operator typo is visible.
    assert_eq!(
        render_template("{nope} {message}", &[("message", "x")]),
        "{nope} x"
    );
    // A substituted value is NOT re-scanned (no accidental re-expansion).
    assert_eq!(
        render_template("{body}", &[("body", "see {time}"), ("time", "T")]),
        "see {time}"
    );
    // Lone/unclosed brace + literal text preserved.
    assert_eq!(render_template("a { b", &[]), "a { b");
    assert_eq!(render_template("100% {x}", &[("x", "ok")]), "100% ok");
}

#[tokio::test]
async fn create_happy_path() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), happy_mocks());
    let r = s.create(req("example.cz")).await.expect("create");
    assert!(r.db.is_some());
    let detail = s
        .get(HostingSelector::Domain(
            Domain::parse("example.cz").expect("parse"),
        ))
        .await
        .expect("get");
    assert_eq!(detail.state, HostingState::Active);
    assert_eq!(detail.system_user, "example_cz");
}

#[tokio::test]
async fn create_rolls_back_on_acme_failure() {
    let pool = open_memory().await.expect("open");
    let mut a = MockAdapterPort::new();
    a.expect_ensure_user().returning(|_, _| Ok(1042));
    a.expect_ensure_dirs().returning(|_, _, _, _| Ok(()));
    a.expect_fpm_ensure().returning(|_, _, _| Ok(()));
    a.expect_db_create().returning(|_, _, _| Ok(db_creds()));
    a.expect_acme_issue()
        .returning(|_, _| Err(AdapterError::Acme("dns".into())));
    // Expect rollbacks for the four prior steps.
    a.expect_db_drop().returning(|_, _, _| Ok(()));
    a.expect_fpm_delete().returning(|_, _| Ok(()));
    a.expect_remove_hosting_tree().returning(|_| Ok(()));
    a.expect_delete_user().returning(|_| Ok(()));
    let s = svc(pool.clone(), a);
    let r = s.create(req("example.cz")).await;
    assert!(r.is_err());
    let row = hostings::get_by_domain(&pool, "example.cz")
        .await
        .expect("query");
    if let Some(r) = row {
        assert_eq!(r.state, HostingState::Failed)
    }
}

#[tokio::test]
async fn create_rolls_back_on_nginx_failure() {
    let pool = open_memory().await.expect("open");
    let mut a = MockAdapterPort::new();
    a.expect_ensure_user().returning(|_, _| Ok(1042));
    a.expect_ensure_dirs().returning(|_, _, _, _| Ok(()));
    a.expect_fpm_ensure().returning(|_, _, _| Ok(()));
    a.expect_db_create().returning(|_, _, _| Ok(db_creds()));
    a.expect_acme_issue().returning(|d, _| Ok(cert_for(d)));
    a.expect_nginx_write_vhost()
        .returning(|_| Err(AdapterError::Other("nginx -t failed".into())));
    a.expect_acme_delete().returning(|_| Ok(()));
    a.expect_db_drop().returning(|_, _, _| Ok(()));
    a.expect_fpm_delete().returning(|_, _| Ok(()));
    a.expect_remove_hosting_tree().returning(|_| Ok(()));
    a.expect_delete_user().returning(|_| Ok(()));
    let s = svc(pool.clone(), a);
    let r = s.create(req("example.cz")).await;
    assert!(r.is_err());
}
