//! Tests for `service::limits`.

use super::*;

/// `server reached pm.max_children` in an FPM log is counted for the
/// site whose pool it names, and only for lines written after the first
/// look.
#[tokio::test]
async fn php_workers_tick_records_pool_saturation() {
    use hyperion_types::phpworkers;
    use std::io::Write;
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), happy_mocks());
    s.create(req("ex.cz")).await.expect("create");
    let d = s
        .get(HostingSelector::Domain(Domain::parse("ex.cz").unwrap()))
        .await
        .expect("get");
    let dir = tempfile::tempdir().expect("dir");
    let log = dir.path().join("php8.3-fpm.log");
    let line = |user: &str| {
        format!("[06-Oct-2026 06:56:45] WARNING: [pool {user}] server reached pm.max_children setting (5), consider raising it\n")
    };
    std::fs::write(&log, line(&d.system_user)).expect("write");
    let mut cursors = std::collections::HashMap::new();

    // First look: history is not news.
    assert_eq!(
        s.php_workers_tick(dir.path(), &mut cursors)
            .await
            .expect("tick"),
        0
    );

    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(&log)
        .expect("open");
    f.write_all(line(&d.system_user).as_bytes())
        .expect("append");
    f.write_all(line(&d.system_user).as_bytes())
        .expect("append");
    f.write_all(line("someone_else").as_bytes())
        .expect("append");
    assert_eq!(
        s.php_workers_tick(dir.path(), &mut cursors)
            .await
            .expect("tick"),
        1
    );
    let st = phpworkers::State::parse(
        &hyperion_state::hosting_kv::get(&pool, d.id.as_str(), phpworkers::KV_STATE)
            .await
            .expect("kv")
            .expect("state"),
    )
    .expect("parse");
    assert_eq!(st.hits_today(st.last_at), 2);
    assert_eq!(st.alerted_at, st.last_at, "first hit alerts");

    // Nothing new: nothing recorded.
    assert_eq!(
        s.php_workers_tick(dir.path(), &mut cursors)
            .await
            .expect("tick"),
        0
    );
}

/// The boot re-render must write each pool WITH its stored limits. It
/// used to render the template defaults, so every agent restart put
/// every site back on 256 MB / five workers and undid the automatic
/// memory_limit without it ever noticing.
#[tokio::test]
async fn boot_rerender_keeps_stored_pool_limits() {
    use std::sync::{Arc, Mutex};
    let pool = open_memory().await.expect("open");
    let seen: Arc<Mutex<Vec<(i64, i64)>>> = Arc::default();
    let mut a = happy_mocks();
    let rec = seen.clone();
    a.expect_apply_php_limits()
        .returning(move |_, _, _, mem, _, children, _| {
            rec.lock().unwrap().push((mem, children));
            Ok(())
        });
    let s = svc(pool, a);
    s.create(req("ex.cz")).await.expect("create");
    let sel = HostingSelector::Domain(Domain::parse("ex.cz").unwrap());
    let mut l = s.get_limits(sel.clone()).await.expect("limits");
    l.php_memory_mb = 512;
    l.php_max_children = 12;
    s.set_limits(sel, l).await.expect("set");
    seen.lock().unwrap().clear();

    assert_eq!(s.rerender_fpm_pools().await, 1);
    assert_eq!(*seen.lock().unwrap(), vec![(512, 12)]);
}

/// Out-of-memory in the site's error.log raises the pool one step; a hand
/// save of the UNCHANGED card keeps the operator's floor, a changed value
/// becomes the new floor; turning the automation off restores the floor.
#[tokio::test]
async fn php_mem_auto_raises_rebases_and_restores() {
    use hyperion_types::phpmem;
    use std::io::Write;
    let pool = open_memory().await.expect("open");
    let home = tempfile::tempdir().expect("dir");
    let mut a = happy_mocks();
    a.expect_apply_php_limits()
        .returning(|_, _, _, _, _, _, _| Ok(()));
    let s = svc(pool.clone(), a).with_paths(HostingPaths {
        home_root: home.path().display().to_string(),
        ..HostingPaths::default()
    });
    s.create(req("ex.cz")).await.expect("create");
    let sel = HostingSelector::Domain(Domain::parse("ex.cz").unwrap());
    let d = s.get(sel.clone()).await.expect("get");
    let id = d.id.as_str().to_string();
    let logs = home
        .path()
        .join(&d.system_user)
        .join(&d.domain)
        .join("logs");
    std::fs::create_dir_all(&logs).expect("mkdir");
    let log = logs.join("error.log");
    std::fs::write(
        &log,
        "Allowed memory size of 268435456 bytes exhausted (old)\n",
    )
    .expect("write");
    hyperion_state::hosting_kv::set(&pool, &id, phpmem::KV_ENABLED, "on", 0)
        .await
        .expect("kv");
    let state = || async {
        phpmem::State::parse(
            &hyperion_state::hosting_kv::get(&pool, &id, phpmem::KV_STATE)
                .await
                .expect("kv")
                .unwrap_or_default(),
        )
    };
    let mem = || async {
        s.get_limits(sel.clone())
            .await
            .expect("limits")
            .php_memory_mb
    };

    // First sight: the history already in the log is not acted on.
    assert_eq!(s.php_mem_auto_tick().await.expect("tick"), 0);
    assert_eq!(mem().await, 256);
    assert_eq!(state().await.expect("state").base_mb, 256);

    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(&log)
        .expect("open");
    f.write_all(
            b"FastCGI sent in stderr: \"PHP message: PHP Fatal error:  Allowed memory size of 268435456 bytes exhausted (tried to allocate 20480 bytes)\"\n",
        )
        .expect("append");
    assert_eq!(s.php_mem_auto_tick().await.expect("tick"), 1);
    assert_eq!(mem().await, 384);
    // Same lines are not read twice, and the cooldown holds anyway.
    assert_eq!(s.php_mem_auto_tick().await.expect("tick"), 0);

    // Saving the card as shown keeps the operator's own 256 as the floor.
    let mut l = s.get_limits(sel.clone()).await.expect("limits");
    s.set_limits(sel.clone(), l.clone()).await.expect("set");
    assert_eq!(state().await.expect("state").base_mb, 256);
    // A new value typed by hand becomes the floor.
    l.php_memory_mb = 320;
    s.set_limits(sel.clone(), l).await.expect("set");
    assert_eq!(state().await.expect("state").base_mb, 320);

    // Raise once more, then switch off: the floor comes back.
    f.write_all(b"Allowed memory size of 335544320 bytes exhausted\n")
        .expect("append");
    let mut st = state().await.expect("state");
    st.last_change_at = 0; // past the cooldown
    hyperion_state::hosting_kv::set(&pool, &id, phpmem::KV_STATE, &st.to_json(), 0)
        .await
        .expect("kv");
    assert_eq!(s.php_mem_auto_tick().await.expect("tick"), 1);
    assert_eq!(mem().await, 448);
    hyperion_state::hosting_kv::set(&pool, &id, phpmem::KV_ENABLED, "off", 0)
        .await
        .expect("kv");
    assert_eq!(s.php_mem_auto_tick().await.expect("tick"), 1);
    assert_eq!(mem().await, 320);
    assert!(state().await.is_none(), "state forgotten once off");
    assert_eq!(s.php_mem_auto_tick().await.expect("tick"), 0);
}

#[tokio::test]
async fn set_limits_clamps_and_persists() {
    let pool = open_memory().await.expect("open");
    let mut a = happy_mocks();
    a.expect_apply_php_limits()
        .returning(|_, _, _, _, _, _, _| Ok(()));
    let s = svc(pool.clone(), a);
    s.create(req("ex.cz")).await.expect("create");
    let sel = HostingSelector::Domain(Domain::parse("ex.cz").unwrap());
    let mut l = hyperion_types::HostingLimits::defaults();
    l.php_memory_mb = 100_000; // nonsense
    l.php_max_children = 0; // nonsense
    let stored = s.set_limits(sel.clone(), l).await.expect("set");
    assert_eq!(stored.php_memory_mb, 8192, "clamped to upper bound");
    assert_eq!(stored.php_max_children, 1, "clamped to lower bound");
    // Round-trip via get_limits
    let l2 = s.get_limits(sel).await.expect("get");
    assert_eq!(l2, stored);
}

#[tokio::test]
async fn get_limits_defaults_when_no_row() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), happy_mocks());
    s.create(req("ex.cz")).await.expect("create");
    let sel = HostingSelector::Domain(Domain::parse("ex.cz").unwrap());
    let l = s.get_limits(sel).await.expect("get");
    assert_eq!(l, hyperion_types::HostingLimits::defaults());
}

/// Happy path: switching from PHP 8.3 (req() default) to 8.4
/// flips the DB row + the agent's view of php_version on get().
/// We don't try to assert mockall expectation counts here (the
/// interaction between happy_mocks's catchall and a withf-
/// constrained one is order-dependent and brittle) — outcome
/// is the source of truth, which is what an operator observes.
#[tokio::test]
async fn set_php_version_happy_path() {
    let pool = open_memory().await.expect("open");
    let mut a = happy_mocks();
    a.expect_fpm_delete().returning(|_, _| Ok(()));
    a.expect_apply_php_limits()
        .returning(|_, _, _, _, _, _, _| Ok(()));
    let s = svc(pool.clone(), a);
    s.create(req("ex.cz")).await.expect("create");
    let sel = HostingSelector::Domain(Domain::parse("ex.cz").unwrap());
    // Confirm starting state.
    let before = s.get(sel.clone()).await.expect("get pre");
    assert_eq!(before.php_version, Some(PhpVersion::V8_3));

    let v = s
        .set_php_version(sel.clone(), PhpVersion::V8_4)
        .await
        .expect("switch");
    assert_eq!(v, PhpVersion::V8_4);
    let after = s.get(sel).await.expect("get post");
    assert_eq!(after.php_version, Some(PhpVersion::V8_4));
}

/// Switching to the SAME version returns Ok(version) and leaves
/// the row untouched — operator can click without churn.
#[tokio::test]
async fn set_php_version_noop_when_unchanged() {
    let pool = open_memory().await.expect("open");
    let mut a = happy_mocks();
    a.expect_fpm_delete().returning(|_, _| Ok(()));
    let s = svc(pool.clone(), a);
    s.create(req("ex.cz")).await.expect("create");
    let sel = HostingSelector::Domain(Domain::parse("ex.cz").unwrap());
    // req() defaults to PhpVersion::V8_3.
    let v = s
        .set_php_version(sel.clone(), PhpVersion::V8_3)
        .await
        .expect("noop");
    assert_eq!(v, PhpVersion::V8_3);
    let after = s.get(sel).await.expect("get");
    assert_eq!(after.php_version, Some(PhpVersion::V8_3));
}

/// A STATIC hosting is converted to PHP rather than refused.
///
/// The old contract answered "delete and recreate as a PHP hosting",
/// which is the worst advice for the case that produces it: an
/// imported WordPress site whose source panel reported no PHP
/// version, so the importer classified it static. Its files and
/// database are already in place.
#[tokio::test]
async fn set_php_version_converts_a_static_hosting() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), happy_mocks());
    let mut r = req("static.cz");
    r.php_version = None;
    r.kind = "static".into();
    r.database = None;
    s.create(r).await.expect("create static");
    let sel = HostingSelector::Domain(Domain::parse("static.cz").unwrap());

    let got = s
        .set_php_version(sel.clone(), PhpVersion::V8_4)
        .await
        .expect("static must convert, not be refused");
    assert_eq!(got, PhpVersion::V8_4);

    // The kind must move too. Leaving it "static" would render the
    // static vhost template over a hosting that now has an FPM pool —
    // a site that 404s every .php it is asked for.
    let after = s.get(sel).await.expect("get");
    assert_eq!(after.php_version, Some(PhpVersion::V8_4));
    assert_eq!(after.kind, "php");
}

/// kind="php" with NO version is what the importer produces when the
/// source panel reported none — the exact site an operator wants to
/// hand a PHP version. The first guard matched only kind="static"
/// and refused these with "hosting kind `php` cannot run PHP".
#[tokio::test]
async fn set_php_version_fills_in_an_imported_php_site_without_a_version() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), happy_mocks());
    let mut r = req("imported.cz");
    r.php_version = None;
    r.kind = "php".into();
    r.database = None;
    s.create(r).await.expect("create imported");
    let sel = HostingSelector::Domain(Domain::parse("imported.cz").unwrap());
    let got = s
        .set_php_version(sel.clone(), PhpVersion::V8_3)
        .await
        .expect("a php-kind site without a version must accept one");
    assert_eq!(got, PhpVersion::V8_3);
    let after = s.get(sel).await.expect("get");
    assert_eq!(after.php_version, Some(PhpVersion::V8_3));
    assert_eq!(after.kind, "php");
}

#[tokio::test]
async fn set_php_version_still_rejects_a_reverse_proxy() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), happy_mocks());
    let mut r = req("proxy.cz");
    r.php_version = None;
    r.kind = "reverse_proxy".into();
    r.proxy_upstream_url = Some("http://127.0.0.1:3000".into());
    r.database = None;
    s.create(r).await.expect("create proxy");
    let sel = HostingSelector::Domain(Domain::parse("proxy.cz").unwrap());
    let err = s
        .set_php_version(sel, PhpVersion::V8_4)
        .await
        .expect_err("a reverse proxy has no docroot");
    assert!(matches!(err, RpcError::Conflict { .. }), "got: {err:?}");
}
