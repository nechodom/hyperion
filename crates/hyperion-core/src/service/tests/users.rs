//! Tests for `service::users`.

use super::*;

/// The whole point of widening the session probe: a privilege taken away
/// must be gone on the NEXT request, not when the cookie happens to
/// expire. Before this, `web_session_touch` returned a bare bool and the
/// role and capabilities came from the cookie, so an admin demoted at
/// 09:00 kept full access until as late as 17:00.
#[tokio::test]
async fn a_demotion_takes_effect_on_the_next_request() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), happy_mocks());
    let uid = s
        .web_user_create(
            "vera".into(),
            "vera@example.cz".into(),
            "correct horse battery".into(),
            "admin".into(),
        )
        .await
        .expect("create user");

    let before = s
        .web_session_touch("sid-not-in-the-ledger", uid)
        .await
        .expect("touch");
    assert!(before.known_user && !before.locked);
    assert_eq!(before.role, "admin");

    s.web_user_set_role(uid, "viewer".into())
        .await
        .expect("demote");

    let after = s
        .web_session_touch("sid-not-in-the-ledger", uid)
        .await
        .expect("touch");
    assert_eq!(after.role, "viewer", "the demotion did not take effect");
    assert!(
        after.caps != before.caps,
        "a viewer must not keep an admin's capabilities"
    );
}

/// A custom role always stores `role = operator`, so giving one to an Owner
/// demotes them. Doing that to the only Owner left the cluster with nobody
/// who can manage users or unlock accounts.
#[tokio::test]
async fn a_custom_role_cannot_demote_the_last_owner() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), happy_mocks());
    let owner = s
        .web_user_create(
            "olga".into(),
            "olga@example.cz".into(),
            "correct horse battery".into(),
            "super_admin".into(),
        )
        .await
        .expect("create owner");
    let role = s
        .role_create("Support".into(), 0, false)
        .await
        .expect("create role");

    let refused = s.web_user_set_custom_role(owner, role).await;
    assert!(
        matches!(refused, Err(RpcError::Validation { .. })),
        "the last Owner was demoted: {refused:?}"
    );
    let kept = hyperion_state::web_users::get_by_id(&pool, owner)
        .await
        .expect("get")
        .expect("owner exists");
    assert_eq!(kept.role, hyperion_state::web_users::WebRole::SuperAdmin);

    // With a second Owner the first one can step down, and the guard then
    // protects the one who remains.
    let second = s
        .web_user_create(
            "pavla".into(),
            "pavla@example.cz".into(),
            "correct horse battery".into(),
            "super_admin".into(),
        )
        .await
        .expect("create second owner");
    s.web_user_set_custom_role(owner, role)
        .await
        .expect("a spare Owner can take a custom role");
    assert!(s.web_user_set_custom_role(second, role).await.is_err());
}

/// The profile page shows a pending email change as "a code went to
/// <address>". So a pending change is reported only while its code can
/// still be entered, and a request that sent nothing must leave none.
#[tokio::test]
async fn web_user_get_reports_only_a_live_pending_email_change() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), happy_mocks());
    let uid = s
        .web_user_create(
            "eda".into(),
            "eda@example.cz".into(),
            "correct horse battery".into(),
            "operator".into(),
        )
        .await
        .expect("create user");

    // No SMTP in the test service: refused, and nothing stashed.
    assert!(s
        .email_change_request(uid, "new@example.cz".into(), "correct horse battery".into())
        .await
        .is_err());
    let u = s.web_user_get(uid).await.expect("get").expect("user");
    assert_eq!(
        u.pending_email, None,
        "a code that never left is not pending"
    );
    // 2FA off: the backup-code count is not reported at all.
    assert_eq!(u.backup_codes_left, None);

    let now = now_secs();
    hyperion_state::web_users::set_pending_email(&pool, uid, "new@example.cz", "h", now + 600, now)
        .await
        .expect("stash");
    let u = s.web_user_get(uid).await.expect("get").expect("user");
    assert_eq!(
        u.pending_email.map(|p| p.new_email).as_deref(),
        Some("new@example.cz")
    );

    hyperion_state::web_users::set_pending_email(&pool, uid, "new@example.cz", "h", now - 1, now)
        .await
        .expect("stash");
    let u = s.web_user_get(uid).await.expect("get").expect("user");
    assert_eq!(u.pending_email, None, "an expired code is not pending");
}

/// Locking is how an admin stops someone NOW. It used to stop only their
/// next login, which is not what the button says.
#[tokio::test]
async fn locking_an_account_ends_its_live_session() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), happy_mocks());
    let uid = s
        .web_user_create(
            "lada".into(),
            "lada@example.cz".into(),
            "correct horse battery".into(),
            "operator".into(),
        )
        .await
        .expect("create user");
    assert!(!s.web_session_touch("sid", uid).await.expect("touch").locked);

    s.web_user_set_locked(uid, true, Some("offboarded".into()))
        .await
        .expect("lock");
    assert!(s.web_session_touch("sid", uid).await.expect("touch").locked);
}
