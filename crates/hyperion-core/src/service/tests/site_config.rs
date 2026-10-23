//! Tests for `service::site_config`.

use super::*;

/// Turning CRS on needs the engine on the node; with it, the rule set is
/// loaded at http level BEFORE the vhost, and unloaded again when the
/// last site turns it off. Bad exclusions are refused by name; a caller
/// that predates the tier keeps the stored settings.
#[tokio::test]
async fn crs_settings_validate_toggle_the_rule_set_and_survive_old_callers() {
    let pool = open_memory().await.expect("open");
    let mut a = happy_mocks();
    a.expect_nginx_delete_htpasswd().returning(|_| Ok(()));
    let available = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let loaded = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (av, ld) = (available.clone(), loaded.clone());
    a.expect_modsec_status()
        .returning(move || hyperion_types::crs::ModsecStatus {
            loaded: ld.load(std::sync::atomic::Ordering::SeqCst),
            ..engine(av.load(std::sync::atomic::Ordering::SeqCst))
        });
    let syncs = std::sync::Arc::new(std::sync::Mutex::new(Vec::<bool>::new()));
    let (sy, ld) = (syncs.clone(), loaded.clone());
    a.expect_modsec_sync_http().returning(move |need| {
        sy.lock().expect("lock").push(need);
        ld.store(need, std::sync::atomic::Ordering::SeqCst);
        Ok(true)
    });
    let s = svc(pool.clone(), a);
    s.create(req("example.cz")).await.expect("create");
    let sel = HostingSelector::Domain(Domain::parse("example.cz").expect("parse"));

    let mut on = vh_defaults();
    on.crs_mode = "block".into();
    let err = s.set_vhost_options(sel.clone(), on.clone(), None).await;
    assert!(format!("{}", err.expect_err("no engine")).contains("install"));
    assert!(syncs.lock().expect("lock").is_empty());

    available.store(true, std::sync::atomic::Ordering::SeqCst);
    on.crs_paranoia = 2;
    on.crs_exclusions = r#"[{"rules":[942100],"path":"/x"}]"#.into();
    s.set_vhost_options(sel.clone(), on.clone(), None)
        .await
        .expect("on");
    assert_eq!(*syncs.lock().expect("lock"), vec![true], "rule set loaded");
    let got = s.get(sel.clone()).await.expect("get").vhost_options;
    assert_eq!(got.crs_mode, "block");
    assert_eq!(got.crs_paranoia, 2);
    assert_eq!(got.crs_threshold, 5, "default filled in");
    assert_eq!(got.crs_exclusions, r#"[{"rules":[942100],"path":"/x"}]"#);
    assert_eq!(s.modsec_status().await.expect("st").active_sites, 1);

    // An older master knows nothing of CRS: everything stays.
    s.set_vhost_options(sel.clone(), vh_defaults(), None)
        .await
        .expect("legacy");
    let got = s.get(sel.clone()).await.expect("get").vhost_options;
    assert_eq!(got.crs_mode, "block");
    assert_eq!(got.crs_exclusions, r#"[{"rules":[942100],"path":"/x"}]"#);
    assert_eq!(syncs.lock().expect("lock").len(), 1, "no toggle, no sync");

    // Re-rendered while the rule set was unloaded (a resume after the
    // boot sync dropped it): it is loaded again before the vhost.
    loaded.store(false, std::sync::atomic::Ordering::SeqCst);
    s.set_vhost_options(sel.clone(), vh_defaults(), None)
        .await
        .expect("re-render");
    assert_eq!(*syncs.lock().expect("lock"), vec![true, true]);

    let mut bad = on.clone();
    bad.crs_exclusions = r#"[{"rules":[949110]}]"#.into();
    let err = s.set_vhost_options(sel.clone(), bad, None).await;
    assert!(format!("{}", err.expect_err("structural")).contains("949110"));
    let mut bad = on.clone();
    bad.crs_paranoia = 4;
    assert!(s.set_vhost_options(sel.clone(), bad, None).await.is_err());

    let mut off = on.clone();
    off.crs_mode = "off".into();
    s.set_vhost_options(sel.clone(), off, None)
        .await
        .expect("off");
    assert_eq!(
        *syncs.lock().expect("lock"),
        vec![true, true, false],
        "rule set unloaded"
    );
    assert_eq!(s.modsec_status().await.expect("st").active_sites, 0);
}

/// An empty level from an older caller keeps the stored level and pins
/// while the bool still agrees with them; flipping the bool decides.
#[tokio::test]
async fn legacy_vhost_save_keeps_waf_level_and_overrides() {
    let pool = open_memory().await.expect("open");
    let mut a = happy_mocks();
    a.expect_nginx_delete_htpasswd().returning(|_| Ok(()));
    let s = svc(pool.clone(), a);
    s.create(req("example.cz")).await.expect("create");
    let sel = HostingSelector::Domain(Domain::parse("example.cz").expect("parse"));
    let mut opts = vh_defaults();
    opts.waf_level = "strict".into();
    opts.waf_overrides = r#"{"dotfiles":true,"xmlrpc":false}"#.into();
    s.set_vhost_options(sel.clone(), opts, None)
        .await
        .expect("set");

    let mut legacy = vh_defaults();
    legacy.waf_enabled = true;
    s.set_vhost_options(sel.clone(), legacy, None)
        .await
        .expect("legacy");
    let got = s.get(sel.clone()).await.expect("get").vhost_options;
    assert_eq!(got.waf_level, "strict");
    assert_eq!(got.waf_overrides, r#"{"dotfiles":true,"xmlrpc":false}"#);

    let legacy_off = vh_defaults();
    s.set_vhost_options(sel.clone(), legacy_off, None)
        .await
        .expect("off");
    let got = s.get(sel.clone()).await.expect("get").vhost_options;
    assert_eq!(got.waf_level, "off");
    assert!(!got.waf_enabled);
    // "Off" from the old switch means no WAF: the rule pinned ON went
    // with it; the pin that only matters once a rule is on stayed.
    assert_eq!(got.waf_overrides, r#"{"xmlrpc":false}"#);

    let mut bad = vh_defaults();
    bad.waf_level = "paranoid".into();
    assert!(s.set_vhost_options(sel, bad, None).await.is_err());
}

/// The expiry warning: a refused send is audited as a failure — and the
/// scheduled row is still completed, because bouncing it back to pending
/// would re-send every tick forever against a relay that keeps refusing.
#[tokio::test]
async fn refused_expiry_warning_is_audited_as_failed_but_still_completes_the_row() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), happy_mocks()).with_email(Some(refusing_relay()), None);
    s.create(req("konci.cz")).await.expect("create");
    let sel = HostingSelector::Domain(Domain::parse("konci.cz").expect("parse"));
    // Expires in 12 h: every warning offset (30/7/1 days) is already due,
    // the suspend is not.
    let mut e = hyperion_types::HostingExpiry::defaults();
    e.expires_at = Some(now_secs() + 43_200);
    e.owner_email = Some("zakaznik@konci.cz".into());
    s.set_expiry(sel, e).await.expect("expiry");

    s.scheduler_tick().await.expect("tick");

    let audit = s.audit_list(200).await.expect("audit");
    let notify: Vec<_> = audit
        .iter()
        .filter(|a| a.action == "scheduler.notify")
        .collect();
    assert!(!notify.is_empty(), "the warnings were due: {audit:?}");
    assert!(
        notify.iter().all(|a| a.result == "failed"),
        "a warning the relay refused is not an 'ok': {notify:?}"
    );
    // Still done, not pending: the customer's next event is the suspend,
    // and an hourly retry storm helps nobody.
    let still_due = hyperion_state::scheduler::pending_due(&pool, now_secs(), 100)
        .await
        .expect("pending");
    assert!(
        !still_due
            .iter()
            .any(|a| a.action.as_str().starts_with("notify_")),
        "a failed send must not bounce the row back to pending: {still_due:?}"
    );
}

#[tokio::test]
async fn suspend_disables_every_login_and_resume_puts_back_exactly_what_was_there() {
    let pool = open_memory().await.expect("open");
    let shadow = FakeShadow::default();
    let mut mocks = with_fake_shadow(offline_cycle_mocks(), &shadow);
    // Expiry, not the password: `usermod -U` would unlock a login that was
    // locked for some other reason.
    mocks.expect_linux_lock_login().times(0);
    mocks.expect_linux_unlock_login().times(0);
    let s = svc(pool.clone(), mocks);
    let site = site_with_extra_login(&s, &pool, &shadow).await;
    let sel = HostingSelector::Id(site.id.clone());

    s.suspend(
        sel.clone(),
        hyperion_types::SuspendReason::Manual { message: None },
    )
    .await
    .expect("suspend");
    {
        let sh = shadow.lock().expect("lock");
        assert_eq!(sh[&site.system_user], "1", "the site user is disabled");
        assert_eq!(sh["web.kos.cz"], "1", "and so is the extra FTP login");
    }

    s.resume(sel).await.expect("resume");
    {
        let sh = shadow.lock().expect("lock");
        assert_eq!(sh[&site.system_user], "", "never expired, as before");
        assert_eq!(
            sh["web.kos.cz"], "20500",
            "the operator's own expiry survives"
        );
    }
    assert!(
        hyperion_state::hosting_kv::get(&pool, site.id.as_str(), LOGIN_LOCK_KV)
            .await
            .expect("kv")
            .is_none(),
        "nothing left to undo, so no record"
    );
}

#[tokio::test]
async fn trashing_a_suspended_site_keeps_the_real_expiry_to_restore() {
    let pool = open_memory().await.expect("open");
    let shadow = FakeShadow::default();
    let mut mocks = with_fake_shadow(offline_cycle_mocks(), &shadow);
    mocks.expect_linux_unlock_login().times(0);
    let s = svc(pool.clone(), mocks);
    let site = site_with_extra_login(&s, &pool, &shadow).await;
    let sel = HostingSelector::Id(site.id.clone());

    s.suspend(
        sel.clone(),
        hyperion_types::SuspendReason::Manual { message: None },
    )
    .await
    .expect("suspend");
    let suspended = s.get(sel.clone()).await.expect("get");
    // A second lock reads "1" from every account. It must not become the
    // value to restore.
    s.trash_hosting(suspended).await.expect("trash");
    s.restore_from_trash(sel).await.expect("restore");

    let sh = shadow.lock().expect("lock");
    assert_eq!(sh[&site.system_user], "");
    assert_eq!(sh["web.kos.cz"], "20500");
}

#[tokio::test]
async fn a_site_suspended_by_an_older_version_is_unlocked_the_old_way() {
    let pool = open_memory().await.expect("open");
    let shadow = FakeShadow::default();
    let mut mocks = with_fake_shadow(offline_cycle_mocks(), &shadow);
    mocks
        .expect_linux_unlock_login()
        .times(1)
        .returning(|_| Ok(()));
    let s = svc(pool.clone(), mocks);
    let site = site_with_extra_login(&s, &pool, &shadow).await;
    // What an older version left: state Suspended, password locked with
    // `usermod -L`, no record.
    hostings::set_state(&pool, &site.id, HostingState::Suspended, now_secs())
        .await
        .expect("legacy suspend");

    // The agent starts: the extra login is closed now, not at resume.
    assert_eq!(s.offline_logins_lock_on_boot().await.expect("boot"), 1);
    assert_eq!(shadow.lock().expect("lock")["web.kos.cz"], "1");

    s.resume(HostingSelector::Id(site.id.clone()))
        .await
        .expect("resume");
    let sh = shadow.lock().expect("lock");
    assert_eq!(sh["web.kos.cz"], "20500");
    assert_eq!(sh[&site.system_user], "");
}

/// A site an older version suspended, suspended AGAIN before the boot pass
/// got to it: the record written then must still say "password-locked by
/// an older version", or the resume would leave that lock in place.
#[tokio::test]
async fn re_suspending_an_old_style_suspension_keeps_its_password_lock_to_undo() {
    let pool = open_memory().await.expect("open");
    let shadow = FakeShadow::default();
    let mut mocks = with_fake_shadow(offline_cycle_mocks(), &shadow);
    mocks
        .expect_linux_unlock_login()
        .times(1)
        .returning(|_| Ok(()));
    let s = svc(pool.clone(), mocks);
    let site = site_with_extra_login(&s, &pool, &shadow).await;
    hostings::set_state(&pool, &site.id, HostingState::Suspended, now_secs())
        .await
        .expect("old-style suspension");
    let sel = HostingSelector::Id(site.id.clone());
    s.suspend(
        sel.clone(),
        hyperion_types::SuspendReason::Manual { message: None },
    )
    .await
    .expect("suspend again");
    assert_eq!(shadow.lock().expect("lock")["web.kos.cz"], "1");
    s.resume(sel).await.expect("resume");
    assert_eq!(shadow.lock().expect("lock")["web.kos.cz"], "20500");
}

/// A suspend this code performs is never mistaken for an old-style one,
/// even by a reconcile that runs before its logins are disabled.
#[tokio::test]
async fn a_reconcile_mid_suspend_does_not_invent_an_old_style_lock() {
    let pool = open_memory().await.expect("open");
    let shadow = FakeShadow::default();
    let mut mocks = with_fake_shadow(offline_cycle_mocks(), &shadow);
    mocks.expect_linux_unlock_login().times(0);
    let s = svc(pool.clone(), mocks);
    let site = site_with_extra_login(&s, &pool, &shadow).await;
    s.suspend(
        HostingSelector::Id(site.id.clone()),
        hyperion_types::SuspendReason::Manual { message: None },
    )
    .await
    .expect("suspend");
    s.offline_logins_reconcile().await.expect("reconcile");
    s.offline_logins_lock_on_boot().await.expect("boot");
    s.resume(HostingSelector::Id(site.id.clone()))
        .await
        .expect("resume");
    assert_eq!(shadow.lock().expect("lock")["web.kos.cz"], "20500");
}

#[tokio::test]
async fn a_login_that_could_not_be_reenabled_stays_on_record_for_the_next_try() {
    let pool = open_memory().await.expect("open");
    let shadow = FakeShadow::default();
    let mut mocks = offline_cycle_mocks();
    let read = shadow.clone();
    mocks
        .expect_linux_login_expiry()
        .returning(move |login| Ok(read.lock().expect("lock").get(login).cloned()));
    let write = shadow.clone();
    let failing = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let still_failing = failing.clone();
    mocks
        .expect_linux_set_login_expiry()
        .returning(move |login, value| {
            if login == "web.kos.cz"
                && value != "1"
                && still_failing.load(std::sync::atomic::Ordering::SeqCst)
            {
                return Err(AdapterError::Other(
                    "usermod: cannot lock /etc/shadow".into(),
                ));
            }
            if let Some(v) = write.lock().expect("lock").get_mut(login) {
                *v = value.to_string();
            }
            Ok(())
        });
    let s = svc(pool.clone(), mocks);
    let site = site_with_extra_login(&s, &pool, &shadow).await;
    let sel = HostingSelector::Id(site.id.clone());
    s.suspend(
        sel.clone(),
        hyperion_types::SuspendReason::Manual { message: None },
    )
    .await
    .expect("suspend");
    s.resume(sel).await.expect("resume");

    let raw = hyperion_state::hosting_kv::get(&pool, site.id.as_str(), LOGIN_LOCK_KV)
        .await
        .expect("kv")
        .expect("record kept");
    let record: LoginLock = serde_json::from_str(&raw).expect("json");
    assert_eq!(
        record.prior_expiry.get("web.kos.cz").map(String::as_str),
        Some("20500"),
        "the failed login keeps its real value for the retry"
    );
    assert!(!record.prior_expiry.contains_key(&site.system_user));

    // The site is Active, so resume() would return at once. The reconcile
    // is what gets the login back once the cause is gone.
    failing.store(false, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(s.offline_logins_reconcile().await.expect("reconcile"), 1);
    assert_eq!(shadow.lock().expect("lock")["web.kos.cz"], "20500");
    assert!(
        hyperion_state::hosting_kv::get(&pool, site.id.as_str(), LOGIN_LOCK_KV)
            .await
            .expect("kv")
            .is_none()
    );
}

/// Hostings can share a system user. The account is disabled only once
/// every hosting on it is offline, comes back with the first one to
/// return, and ends with its real expiry whatever the order — never with
/// the "1" the second lock would have read.
#[tokio::test]
async fn sites_sharing_a_system_user_get_it_back_in_either_order() {
    for a_returns_first in [true, false] {
        let pool = open_memory().await.expect("open");
        let shadow = FakeShadow::default();
        let s = svc(
            pool.clone(),
            with_fake_shadow(offline_cycle_mocks(), &shadow),
        );
        let a = site_with_extra_login(&s, &pool, &shadow).await;
        let suid = hyperion_state::system_users::get_by_name(&pool, &a.system_user)
            .await
            .expect("user row")
            .expect("present")
            .id;
        let b_id = HostingId::new_v7();
        hostings::insert(&pool, &b_id, "druhy.cz", suid, None, "/r", now_secs(), None)
            .await
            .expect("second hosting on the same user");
        let (sel_a, sel_b) = (
            HostingSelector::Id(a.id.clone()),
            HostingSelector::Id(b_id.clone()),
        );
        let manual = || hyperion_types::SuspendReason::Manual { message: None };
        s.suspend(sel_a.clone(), manual()).await.expect("suspend a");
        s.suspend(sel_b.clone(), manual()).await.expect("suspend b");

        let (first, second) = if a_returns_first {
            (sel_a, sel_b)
        } else {
            (sel_b, sel_a)
        };
        assert_eq!(
            shadow.lock().expect("lock")[&a.system_user],
            "1",
            "disabled once both are offline"
        );
        s.resume(first).await.expect("first resume");
        assert_eq!(
            shadow.lock().expect("lock")[&a.system_user],
            "",
            "back for the site that is online again (a first: {a_returns_first})"
        );
        s.resume(second).await.expect("second resume");
        let sh = shadow.lock().expect("lock");
        assert_eq!(
            sh[&a.system_user], "",
            "the real value is back once both are (a first: {a_returns_first})"
        );
        assert_eq!(sh["web.kos.cz"], "20500");
    }
}

/// Suspending one of two sites on the same system user must not take the
/// account away from the one that is still online.
#[tokio::test]
async fn suspending_one_site_leaves_a_shared_user_working_for_the_live_one() {
    let pool = open_memory().await.expect("open");
    let shadow = FakeShadow::default();
    let s = svc(
        pool.clone(),
        with_fake_shadow(offline_cycle_mocks(), &shadow),
    );
    let a = site_with_extra_login(&s, &pool, &shadow).await;
    let suid = hyperion_state::system_users::get_by_name(&pool, &a.system_user)
        .await
        .expect("user row")
        .expect("present")
        .id;
    hostings::insert(
        &pool,
        &HostingId::new_v7(),
        "zivy.cz",
        suid,
        None,
        "/r",
        now_secs(),
        None,
    )
    .await
    .expect("live sibling");
    s.suspend(
        HostingSelector::Id(a.id.clone()),
        hyperion_types::SuspendReason::Manual { message: None },
    )
    .await
    .expect("suspend");
    let sh = shadow.lock().expect("lock");
    assert_eq!(sh[&a.system_user], "", "the live site keeps its account");
    assert_eq!(
        sh["web.kos.cz"], "1",
        "the suspended site's own login is closed"
    );
}

/// The review's case: after one of two sharing sites is back online, an
/// agent restart (boot pass) and trashing the other one must not take the
/// account away from the site that is online.
#[tokio::test]
async fn a_restart_or_a_trash_never_disables_a_user_a_live_site_needs() {
    let pool = open_memory().await.expect("open");
    let shadow = FakeShadow::default();
    let s = svc(
        pool.clone(),
        with_fake_shadow(offline_cycle_mocks(), &shadow),
    );
    let a = site_with_extra_login(&s, &pool, &shadow).await;
    let b = sibling_on_same_user(&pool, &a, "druhy.cz").await;
    let manual = || hyperion_types::SuspendReason::Manual { message: None };
    s.suspend(HostingSelector::Id(a.id.clone()), manual())
        .await
        .expect("suspend a");
    s.suspend(HostingSelector::Id(b.clone()), manual())
        .await
        .expect("suspend b");
    assert_eq!(shadow.lock().expect("lock")[&a.system_user], "1");
    s.resume(HostingSelector::Id(a.id.clone()))
        .await
        .expect("resume a");
    assert_eq!(shadow.lock().expect("lock")[&a.system_user], "");

    s.offline_logins_lock_on_boot().await.expect("boot");
    assert_eq!(
        shadow.lock().expect("lock")[&a.system_user],
        "",
        "after a restart"
    );
    let b_detail = s.get(HostingSelector::Id(b.clone())).await.expect("get b");
    s.trash_hosting(b_detail).await.expect("trash b");
    assert_eq!(
        shadow.lock().expect("lock")[&a.system_user],
        "",
        "after trashing b"
    );
    s.offline_logins_reconcile().await.expect("reconcile");
    assert_eq!(
        shadow.lock().expect("lock")[&a.system_user],
        "",
        "after a reconcile"
    );
}

/// Deleting one of two offline sites on a user must not reopen the user
/// for the one still offline; it opens when that one returns.
#[tokio::test]
async fn deleting_one_offline_site_keeps_the_other_offline_sites_user_closed() {
    let pool = open_memory().await.expect("open");
    let shadow = FakeShadow::default();
    let mut mocks = with_fake_shadow(offline_cycle_mocks(), &shadow);
    mocks.expect_nginx_delete_vhost().returning(|_, _| Ok(()));
    mocks.expect_acme_delete().returning(|_| Ok(()));
    mocks.expect_db_drop().returning(|_, _, _| Ok(()));
    mocks.expect_remove_hosting_tree().returning(|_| Ok(()));
    mocks.expect_delete_user().times(0);
    let s = svc(pool.clone(), mocks);
    let a = site_with_extra_login(&s, &pool, &shadow).await;
    let b = sibling_on_same_user(&pool, &a, "druhy.cz").await;
    let manual = || hyperion_types::SuspendReason::Manual { message: None };
    s.suspend(HostingSelector::Id(a.id.clone()), manual())
        .await
        .expect("suspend a");
    s.suspend(HostingSelector::Id(b.clone()), manual())
        .await
        .expect("suspend b");

    s.delete(
        HostingSelector::Id(b),
        hyperion_rpc::wire::DeleteOpts::default(),
    )
    .await
    .expect("delete b");
    assert_eq!(
        shadow.lock().expect("lock")[&a.system_user],
        "1",
        "a is still suspended"
    );
    s.resume(HostingSelector::Id(a.id.clone()))
        .await
        .expect("resume a");
    assert_eq!(shadow.lock().expect("lock")[&a.system_user], "");
}

/// A new site on an account whose other sites are all offline gets it back.
#[tokio::test]
async fn a_new_site_on_a_disabled_user_re_enables_it() {
    let pool = open_memory().await.expect("open");
    let shadow = FakeShadow::default();
    let s = svc(
        pool.clone(),
        with_fake_shadow(offline_cycle_mocks(), &shadow),
    );
    let a = site_with_extra_login(&s, &pool, &shadow).await;
    s.suspend(
        HostingSelector::Id(a.id.clone()),
        hyperion_types::SuspendReason::Manual { message: None },
    )
    .await
    .expect("suspend");
    assert_eq!(shadow.lock().expect("lock")[&a.system_user], "1");
    sibling_on_same_user(&pool, &a, "novy.cz").await;
    s.apply_system_user_policy(&a.system_user).await;
    let sh = shadow.lock().expect("lock");
    assert_eq!(sh[&a.system_user], "", "the new site needs the account");
    assert_eq!(
        sh["web.kos.cz"], "1",
        "the suspended site's own login stays closed"
    );
}

/// A hard delete that keeps the system user must give its logins back:
/// the record goes with the row and nothing else clears the expiry.
#[tokio::test]
async fn deleting_a_suspended_site_but_keeping_its_user_re_enables_the_user() {
    let pool = open_memory().await.expect("open");
    let shadow = FakeShadow::default();
    let mut mocks = with_fake_shadow(offline_cycle_mocks(), &shadow);
    mocks.expect_nginx_delete_vhost().returning(|_, _| Ok(()));
    mocks.expect_acme_delete().returning(|_| Ok(()));
    mocks.expect_db_drop().returning(|_, _, _| Ok(()));
    mocks.expect_remove_hosting_tree().returning(|_| Ok(()));
    mocks.expect_delete_user().times(0);
    let s = svc(pool.clone(), mocks);
    let site = site_with_extra_login(&s, &pool, &shadow).await;
    let sel = HostingSelector::Id(site.id.clone());
    s.suspend(
        sel.clone(),
        hyperion_types::SuspendReason::Manual { message: None },
    )
    .await
    .expect("suspend");
    s.delete(
        sel,
        hyperion_rpc::wire::DeleteOpts {
            keep_user: true,
            keep_database: false,
        },
    )
    .await
    .expect("delete");
    let sh = shadow.lock().expect("lock");
    assert_eq!(sh[&site.system_user], "", "the kept user works again");
    assert_eq!(
        sh["web.kos.cz"], "1",
        "a login of the deleted site that outlived the teardown stays shut"
    );
}

#[tokio::test]
async fn suspend_sets_state_and_writes_suspension_row() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), suspend_mocks());
    s.create(req("ex.cz")).await.expect("create");
    let sel = HostingSelector::Domain(Domain::parse("ex.cz").unwrap());
    s.suspend(
        sel.clone(),
        hyperion_types::SuspendReason::Manual {
            message: Some("over quota".into()),
        },
    )
    .await
    .expect("suspend");
    let detail = s.get(sel).await.expect("get");
    assert_eq!(detail.state, HostingState::Suspended);
    let row = hyperion_state::limits::get_suspension(&pool, &detail.id)
        .await
        .expect("get")
        .expect("present");
    assert_eq!(row.suspended_by, "manual");
    assert_eq!(row.reason_message.as_deref(), Some("over quota"));
}

#[tokio::test]
async fn suspend_is_idempotent_for_already_suspended() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), suspend_mocks());
    s.create(req("ex.cz")).await.expect("create");
    let sel = HostingSelector::Domain(Domain::parse("ex.cz").unwrap());
    s.suspend(sel.clone(), hyperion_types::SuspendReason::Expired)
        .await
        .expect("first");
    // Second call is a no-op; no extra adapter calls beyond what
    // suspend_mocks already allows. Should succeed.
    s.suspend(sel, hyperion_types::SuspendReason::Expired)
        .await
        .expect("idempotent");
}

#[tokio::test]
async fn suspend_reason_upgrades_overdisk_to_manual_but_not_back() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), suspend_mocks());
    let created = s.create(req("ex.cz")).await.expect("create");
    let sel = HostingSelector::Id(created.id.clone());

    // Auto over-disk suspend first.
    s.suspend(sel.clone(), hyperion_types::SuspendReason::OverDisk)
        .await
        .expect("over-disk suspend");
    let row = hyperion_state::limits::get_suspension(&pool, &created.id)
        .await
        .expect("get")
        .expect("present");
    assert_eq!(row.suspended_by, "over-disk");

    // Operator manually suspends the already-down site → reason UPGRADES,
    // so the quota loop (which only resumes its own "over-disk" holds) will
    // leave it alone.
    s.suspend(
        sel.clone(),
        hyperion_types::SuspendReason::Manual {
            message: Some("non-payment".into()),
        },
    )
    .await
    .expect("manual suspend");
    let row = hyperion_state::limits::get_suspension(&pool, &created.id)
        .await
        .expect("get")
        .expect("present");
    assert_eq!(row.suspended_by, "manual", "manual outranks over-disk");
    assert_eq!(row.reason_message.as_deref(), Some("non-payment"));

    // A lower-priority automated reason must NOT downgrade the manual hold.
    s.suspend(sel, hyperion_types::SuspendReason::OverBandwidth)
        .await
        .expect("over-bandwidth suspend");
    let row = hyperion_state::limits::get_suspension(&pool, &created.id)
        .await
        .expect("get")
        .expect("present");
    assert_eq!(
        row.suspended_by, "manual",
        "over-bandwidth must not downgrade a manual hold"
    );
}

#[tokio::test]
async fn suspend_refuses_when_already_deleting() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), suspend_mocks());
    let created = s.create(req("ex.cz")).await.expect("create");
    // Force into 'deleting' directly.
    hyperion_state::hostings::set_state(&pool, &created.id, HostingState::Deleting, now_secs())
        .await
        .expect("set");
    let sel = HostingSelector::Id(created.id.clone());
    let r = s
        .suspend(sel, hyperion_types::SuspendReason::Manual { message: None })
        .await;
    match r {
        Err(RpcError::Conflict { .. }) => {}
        other => panic!("expected Conflict, got {other:?}"),
    }
}

#[tokio::test]
async fn resume_brings_back_to_active() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), resume_mocks());
    s.create(req("ex.cz")).await.expect("create");
    let sel = HostingSelector::Domain(Domain::parse("ex.cz").unwrap());
    s.suspend(sel.clone(), hyperion_types::SuspendReason::Expired)
        .await
        .expect("suspend");
    s.resume(sel.clone()).await.expect("resume");
    let detail = s.get(sel).await.expect("get");
    assert_eq!(detail.state, HostingState::Active);
    let susp = hyperion_state::limits::get_suspension(&pool, &detail.id)
        .await
        .expect("get");
    assert!(susp.is_none(), "suspension row removed on resume");
}

/// A reverse proxy serves an upstream and has no document root to run
/// PHP from, so it is still refused — giving it a pool would produce
/// a site that silently does not work.
/// Editing a SUSPENDED site must not bring it back online.
///
/// nginx_write_vhost renders the serving vhost with no idea what state the
/// hosting is in. set_php_version happens to refuse on a suspended site
/// already ("resume first"), but the alias and vhost-option editors did
/// not — so an alias edit quietly un-suspended a customer who had not
/// paid. The serving writer must not be touched at all here.
#[tokio::test]
async fn editing_aliases_on_a_suspended_site_does_not_unsuspend_it() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let pool = open_memory().await.expect("open");
    let serving = std::sync::Arc::new(AtomicUsize::new(0));
    let counter = serving.clone();
    // Built from scratch: mockall matches expectations in REGISTRATION
    // order, so a permissive nginx_write_vhost inherited from a helper
    // would win and the counter would never move.
    let mut a = MockAdapterPort::new();
    a.expect_nginx_write_vhost().returning(move |_| {
        counter.fetch_add(1, Ordering::Relaxed);
        Ok(())
    });
    a.expect_ensure_user().returning(|_, _| Ok(1042));
    a.expect_ensure_dirs().returning(|_, _, _, _| Ok(()));
    a.expect_fpm_ensure().returning(|_, _, _| Ok(()));
    a.expect_db_create().returning(|_, _, _| Ok(db_creds()));
    a.expect_acme_issue().returning(|d, _| Ok(cert_for(d)));
    a.expect_redis_is_available().returning(|| true);
    a.expect_nginx_apply_suspended().returning(|_, _, _| Ok(()));
    a.expect_fpm_delete().returning(|_, _| Ok(()));
    a.expect_db_lock().returning(|_, _| Ok(()));
    a.expect_linux_lock_login().returning(|_| Ok(()));
    a.expect_linux_login_expiry()
        .returning(|_| Ok(Some(String::new())));
    a.expect_linux_set_login_expiry().returning(|_, _| Ok(()));
    a.expect_kill_user_procs().returning(|_| Ok(()));
    let s = svc(pool.clone(), a);
    s.create(req("paused2.cz")).await.expect("create");
    let sel = HostingSelector::Domain(Domain::parse("paused2.cz").unwrap());
    s.suspend(
        sel.clone(),
        hyperion_types::SuspendReason::Manual {
            message: Some("Unpaid".into()),
        },
    )
    .await
    .expect("suspend");
    let after_suspend = serving.load(Ordering::Relaxed);

    s.hosting_set_aliases(
        sel.clone(),
        vec![Domain::parse("www.paused2.cz").expect("alias")],
    )
    .await
    .expect("alias edit");

    assert_eq!(
        serving.load(Ordering::Relaxed),
        after_suspend,
        "the SERVING vhost was written for a suspended site — that puts a \
             non-paying customer back online as a side effect of an unrelated edit"
    );
    assert_eq!(
        s.get(sel).await.expect("get").state,
        HostingState::Suspended
    );
}

#[tokio::test]
async fn set_proxy_upstream_validates_persists_and_rejects_non_proxy() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), happy_mocks());

    // A reverse proxy: the new upstream is validated, re-serialized and
    // stored, and the returned detail reflects it.
    let mut r = req("proxy.cz");
    r.php_version = None;
    r.kind = "reverse_proxy".into();
    r.proxy_upstream_url = Some("http://127.0.0.1:3000".into());
    r.database = None;
    s.create(r).await.expect("create proxy");
    let sel = HostingSelector::Domain(Domain::parse("proxy.cz").unwrap());

    let updated = s
        .set_proxy_upstream(sel.clone(), "http://10.0.0.5:8080".into())
        .await
        .expect("set upstream");
    assert_eq!(
        updated.proxy_upstream_url.as_deref(),
        Some("http://10.0.0.5:8080/")
    );
    // Persisted, not just returned.
    assert_eq!(
        s.get(sel.clone())
            .await
            .expect("get")
            .proxy_upstream_url
            .as_deref(),
        Some("http://10.0.0.5:8080/")
    );

    // A garbage URL is rejected (chokepoint validator), leaving the
    // stored upstream untouched.
    let err = s
        .set_proxy_upstream(sel.clone(), "not a url; rm -rf".into())
        .await
        .expect_err("garbage upstream");
    assert!(matches!(err, RpcError::Validation { .. }), "got: {err:?}");
    assert_eq!(
        s.get(sel).await.expect("get").proxy_upstream_url.as_deref(),
        Some("http://10.0.0.5:8080/"),
        "a rejected save must not clobber the stored upstream"
    );

    // A plain PHP hosting is not a proxy — the call is refused. Fresh
    // service so the create's adapter expectations stand on their own.
    let pool2 = open_memory().await.expect("open");
    let s2 = svc(pool2.clone(), happy_mocks());
    s2.create(req("php.cz")).await.expect("create php");
    let php_sel = HostingSelector::Domain(Domain::parse("php.cz").unwrap());
    let err = s2
        .set_proxy_upstream(php_sel, "http://127.0.0.1:9000".into())
        .await
        .expect_err("not a reverse proxy");
    assert!(matches!(err, RpcError::Validation { .. }), "got: {err:?}");
}

#[tokio::test]
async fn set_vhost_options_rejects_oversized_hsts() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), happy_mocks());
    s.create(req("example.cz")).await.expect("create");
    let sel = HostingSelector::Domain(Domain::parse("example.cz").unwrap());
    let mut opts = vh_defaults();
    opts.hsts_max_age = 100_000_000; // > 2y → reject
    let r = s.set_vhost_options(sel, opts, None).await;
    assert!(r.is_err(), "expected validation error");
    let e = r.unwrap_err();
    assert!(format!("{e}").contains("hsts_max_age"));
}

#[tokio::test]
async fn set_vhost_options_rejects_bad_redirect_url() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), happy_mocks());
    s.create(req("example.cz")).await.expect("create");
    let sel = HostingSelector::Domain(Domain::parse("example.cz").unwrap());
    let mut opts = vh_defaults();
    // Missing scheme.
    opts.redirect_url = "new.example.cz".into();
    let r = s.set_vhost_options(sel, opts, None).await;
    assert!(r.is_err());
    assert!(format!("{}", r.unwrap_err()).contains("redirect_url"));
}

#[tokio::test]
async fn set_vhost_options_rejects_bad_redirect_code() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), happy_mocks());
    s.create(req("example.cz")).await.expect("create");
    let sel = HostingSelector::Domain(Domain::parse("example.cz").unwrap());
    let mut opts = vh_defaults();
    opts.redirect_code = 418; // ☕
    let r = s.set_vhost_options(sel, opts, None).await;
    assert!(r.is_err());
    assert!(format!("{}", r.unwrap_err()).contains("redirect_code"));
}

#[tokio::test]
async fn set_vhost_options_rejects_basic_auth_without_username() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), happy_mocks());
    s.create(req("example.cz")).await.expect("create");
    let sel = HostingSelector::Domain(Domain::parse("example.cz").unwrap());
    let mut opts = vh_defaults();
    opts.basic_auth_enabled = true;
    opts.basic_auth_user = "  ".into(); // whitespace-only
    let r = s.set_vhost_options(sel, opts, Some("hunter2".into())).await;
    assert!(r.is_err());
    assert!(format!("{}", r.unwrap_err()).contains("basic_auth_user"));
}

#[tokio::test]
async fn set_vhost_options_rejects_oversized_snippet() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), happy_mocks());
    s.create(req("example.cz")).await.expect("create");
    let sel = HostingSelector::Domain(Domain::parse("example.cz").unwrap());
    let mut opts = vh_defaults();
    opts.custom_nginx_snippet = "x".repeat(33 * 1024);
    let r = s.set_vhost_options(sel, opts, None).await;
    assert!(r.is_err());
    assert!(format!("{}", r.unwrap_err()).contains("custom_nginx_snippet"));
}

#[tokio::test]
async fn set_vhost_options_default_ttl_when_cache_on() {
    // Operator turned on FastCGI cache but didn't set TTL → 300s default.
    let pool = open_memory().await.expect("open");
    let mut a = happy_mocks();
    a.expect_nginx_write_htpasswd().returning(|_, _, _| Ok(()));
    a.expect_nginx_delete_htpasswd().returning(|_| Ok(()));
    let s = svc(pool.clone(), a);
    s.create(req("example.cz")).await.expect("create");
    let sel = HostingSelector::Domain(Domain::parse("example.cz").unwrap());
    let mut opts = vh_defaults();
    opts.fastcgi_cache_enabled = true;
    let r = s.set_vhost_options(sel, opts, None).await.expect("apply");
    assert_eq!(r.fastcgi_cache_ttl, 300);
}

#[tokio::test]
async fn set_vhost_options_writes_htpasswd_when_password_supplied() {
    let pool = open_memory().await.expect("open");
    let mut a = happy_mocks();
    a.expect_nginx_write_htpasswd()
        .withf(|hid, user, hash| !hid.is_empty() && user == "preview" && hash.starts_with("$2"))
        .returning(|_, _, _| Ok(()));
    a.expect_nginx_delete_htpasswd().returning(|_| Ok(()));
    let s = svc(pool.clone(), a);
    s.create(req("example.cz")).await.expect("create");
    let sel = HostingSelector::Domain(Domain::parse("example.cz").unwrap());
    let mut opts = vh_defaults();
    opts.basic_auth_enabled = true;
    opts.basic_auth_user = "preview".into();
    let r = s
        .set_vhost_options(sel, opts, Some("hunter2!".into()))
        .await
        .expect("apply");
    assert!(r.basic_auth_set);
}

// ───────── WP debug + Redis ─────────

#[tokio::test]
async fn set_wp_debug_writes_through_to_adapter() {
    let pool = open_memory().await.expect("open");
    let mut a = happy_mocks();
    a.expect_wp_set_debug()
        .withf(|user, _htdocs, enabled, log, display| {
            user == "example_cz" && *enabled && *log && !*display
        })
        .times(1)
        .returning(|_, _, _, _, _| Ok(()));
    let s = svc(pool.clone(), a);
    s.create(req("example.cz")).await.expect("create");
    let sel = HostingSelector::Domain(Domain::parse("example.cz").unwrap());
    let r = s.set_wp_debug(sel, true, true, false).await.expect("set");
    assert!(r.wp_debug_enabled);
    assert!(r.wp_debug_log);
    assert!(!r.wp_debug_display);
}

#[tokio::test]
async fn set_redis_provisions_acl_writes_wp_config_persists() {
    let pool = open_memory().await.expect("open");
    let mut a = happy_mocks();
    // First enable: ACL + wp config write.
    a.expect_redis_ensure_acl()
        .withf(|user, _pw, db| user.starts_with("r_") && *db == 0)
        .times(1)
        .returning(|_, _, _| Ok(()));
    a.expect_wp_set_redis()
        .withf(|_, _, cfg| cfg.is_some())
        .times(1)
        .returning(|_, _, _| Ok(()));
    let s = svc(pool.clone(), a);
    s.create(req("example.cz")).await.expect("create");
    let sel = HostingSelector::Domain(Domain::parse("example.cz").unwrap());
    let r = s.set_redis(sel, true).await.expect("enable");
    assert!(r.redis_enabled);
    assert_eq!(r.redis_db_number, Some(0)); // first free slot
    assert!(r.redis_password_set);
}

#[tokio::test]
async fn set_redis_disable_cleans_up() {
    let pool = open_memory().await.expect("open");
    let mut a = happy_mocks();
    a.expect_redis_ensure_acl().returning(|_, _, _| Ok(()));
    a.expect_wp_set_redis().returning(|_, _, _| Ok(()));
    a.expect_redis_delete_acl()
        .withf(|user| user.starts_with("r_"))
        .times(1)
        .returning(|_| Ok(()));
    let s = svc(pool.clone(), a);
    s.create(req("example.cz")).await.expect("create");
    let sel = HostingSelector::Domain(Domain::parse("example.cz").unwrap());
    // Enable then disable.
    s.set_redis(sel.clone(), true).await.expect("enable");
    let r = s.set_redis(sel, false).await.expect("disable");
    assert!(!r.redis_enabled);
    assert!(r.redis_db_number.is_none());
}

#[tokio::test]
async fn rotate_redis_password_rejects_when_redis_off() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), happy_mocks());
    s.create(req("example.cz")).await.expect("create");
    let sel = HostingSelector::Domain(Domain::parse("example.cz").unwrap());
    let r = s.rotate_redis_password(sel).await;
    assert!(r.is_err());
    assert!(format!("{}", r.unwrap_err()).contains("not enabled"));
}

#[tokio::test]
async fn redis_username_for_is_stable_and_short() {
    let u1 = redis_username_for("01HVXXXXXXYYY");
    let u2 = redis_username_for("01HVXXXXXXYYY"); // same → same
    assert_eq!(u1, u2);
    assert_eq!(u1, "r_01hvxxxx"); // 8 chars + r_ prefix, lowercased
    assert!(u1.len() <= 12);
}

#[tokio::test]
async fn set_vhost_options_rollback_on_nginx_failure() {
    let pool = open_memory().await.expect("open");
    let mut a = MockAdapterPort::new();
    a.expect_ensure_user().returning(|_, _| Ok(1042));
    a.expect_ensure_dirs().returning(|_, _, _, _| Ok(()));
    a.expect_fpm_ensure().returning(|_, _, _| Ok(()));
    a.expect_db_create().returning(|_, _, _| Ok(db_creds()));
    a.expect_acme_issue().returning(|d, _| Ok(cert_for(d)));
    a.expect_nginx_delete_htpasswd().returning(|_| Ok(()));
    // First nginx_write_vhost (during create) succeeds, second
    // (during set_vhost_options) fails → service should roll back
    // the DB options to the previous defaults.
    let mut seq = mockall::Sequence::new();
    a.expect_nginx_write_vhost()
        .times(1)
        .in_sequence(&mut seq)
        .returning(|_| Ok(()));
    a.expect_nginx_write_vhost()
        .times(1)
        .in_sequence(&mut seq)
        .returning(|_| Err(AdapterError::Other("nginx: emerg: invalid".into())));
    let s = svc(pool.clone(), a);
    s.create(req("example.cz")).await.expect("create");
    let sel = HostingSelector::Domain(Domain::parse("example.cz").unwrap());
    let mut opts = vh_defaults();
    opts.maintenance_mode = true;
    opts.hsts_max_age = 31_536_000;
    let r = s.set_vhost_options(sel.clone(), opts, None).await;
    assert!(r.is_err(), "expected nginx rejection");
    // DB should be back to defaults.
    let detail_back = s.get(sel).await.expect("get");
    assert!(!detail_back.vhost_options.maintenance_mode);
    assert_eq!(detail_back.vhost_options.hsts_max_age, 0);
}
