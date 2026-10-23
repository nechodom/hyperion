//! `HostingService` tests: shared fixtures here, one file per service
//! module with the tests of that domain.

use super::*;
use crate::SecretsStore;
use hyperion_state::db::open_memory;
use hyperion_types::{CertInfo, DbProvision};
use hyperion_validate::Domain;
use mockall::predicate::*;

/// Replay probe results through the decision `monitor_tick` makes each
/// sample — same history window, same state bookkeeping — and return the
/// (sample index, transition) pairs an operator would have been sent.
fn replay_monitor(
    results: &[bool],
    threshold: i64,
    hard: bool,
) -> Vec<(usize, super::MonitorTransition)> {
    let probes: Vec<Probe> = results
        .iter()
        .map(|ok| match (ok, hard) {
            (true, _) => Probe::Ok,
            (false, false) => Probe::Soft,
            (false, true) => Probe::Hard,
        })
        .collect();
    replay_probes(&probes, threshold)
}

/// One probe outcome, as `monitor_tick` sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Probe {
    Ok,
    /// No answer / timeout / 4xx.
    Soft,
    /// 5xx or an error page.
    Hard,
}

fn replay_probes(probes: &[Probe], threshold: i64) -> Vec<(usize, super::MonitorTransition)> {
    let window = (threshold * 2).max(4) as usize;
    let mut samples: Vec<(i64, bool)> = Vec::new();
    let mut alerting = false;
    let mut last_change_at = None;
    let mut sent = Vec::new();
    for (i, p) in probes.iter().enumerate() {
        let at = 1_000 + 60 * i as i64;
        samples.push((at, *p == Probe::Ok));
        let recent = &samples[samples.len().saturating_sub(window)..];
        if let Some(t) = super::monitor_transition(
            alerting,
            last_change_at,
            recent,
            threshold,
            *p == Probe::Hard,
        ) {
            alerting = t == super::MonitorTransition::Down;
            last_change_at = Some(at);
            sent.push((i, t));
        }
    }
    sent
}

/// What the local test site does with each request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SiteMode {
    /// 200 with a normal page.
    Up,
    /// TLS handshake, then hang up without a byte of HTTP: curl gets no
    /// status at all — the production failures (no status, no error text).
    Silent,
    /// Status line and headers, then the connection drops before the
    /// body: curl exits non-zero holding an empty 200.
    HeadersThenDrop,
    /// A real 500.
    ServerError,
    /// A clean, complete 200 with nothing in it (white screen).
    Empty,
    /// A 200 carrying the WordPress critical-error page.
    WpCritical,
    /// A normal page after this many seconds.
    Slow(u64),
}

/// A local HTTPS site on 127.0.0.1 whose behaviour the test switches.
struct TestSite {
    port: u16,
    mode: std::sync::Arc<std::sync::Mutex<SiteMode>>,
}

impl TestSite {
    fn set(&self, m: SiteMode) {
        *self.mode.lock().expect("mode") = m;
    }
    /// What goes where the domain goes: the probe builds `https://{host}/`.
    fn host(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }
}

/// The probe shells out to the real curl; without it there is nothing
/// to test (CI and every node have it).
fn curl_missing() -> bool {
    let missing = !std::path::Path::new("/usr/bin/curl").exists();
    if missing {
        eprintln!("skipped: /usr/bin/curl not installed");
    }
    missing
}

async fn spawn_test_site() -> TestSite {
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let key = rcgen::KeyPair::generate().expect("keypair");
    let mut params =
        rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("cert params");
    params.distinguished_name = rcgen::DistinguishedName::new();
    let cert = params.self_signed(&key).expect("self-signed");
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("tls versions")
    .with_no_client_auth()
    .with_single_cert(
        vec![cert.der().clone()],
        rustls::pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into()),
    )
    .expect("tls config");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let mode = Arc::new(Mutex::new(SiteMode::Up));
    let shared = mode.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let mode = shared.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let mut head = Vec::new();
                let mut chunk = [0u8; 2048];
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    match tls.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => head.extend_from_slice(&chunk[..n]),
                    }
                }
                let page = |status: &str, body: &str| {
                    format!(
                        "HTTP/1.1 {status}\r\nContent-Type: text/html\r\n\
                             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                };
                let ok = "<html><body><h1>Shop</h1></body></html>";
                let m = *mode.lock().expect("mode");
                let reply = match m {
                    SiteMode::Silent => return,
                    SiteMode::HeadersThenDrop => {
                        let _ = tls
                            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5000\r\n\r\n")
                            .await;
                        let _ = tls.flush().await;
                        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                        return;
                    }
                    SiteMode::Up => page("200 OK", ok),
                    SiteMode::ServerError => page("500 Internal Server Error", "oops"),
                    SiteMode::Empty => page("200 OK", ""),
                    SiteMode::WpCritical => page(
                        "200 OK",
                        "<p>There has been a critical error on this website.</p>",
                    ),
                    SiteMode::Slow(secs) => {
                        tokio::time::sleep(std::time::Duration::from_secs(secs)).await;
                        page("200 OK", ok)
                    }
                };
                let _ = tls.write_all(reply.as_bytes()).await;
                let _ = tls.shutdown().await;
            });
        }
    });
    TestSite { port, mode }
}

/// A hosting monitored against `site`, plus an admin to receive the bell.
async fn monitored_site(site: &TestSite) -> (HostingService<MockAdapterPort>, SqlitePool, String) {
    use hyperion_state::web_users::WebRole;
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), package_mocks());
    seed_web_user(&s, "boss", WebRole::Admin).await;
    let h = hosting_for_packages(&s, "mon.cz").await;
    // `create` switched monitoring on (every 60 s, alert after 3); point
    // the probe at the local site.
    sqlx::query("UPDATE hostings SET domain = ? WHERE id = ?")
        .bind(site.host())
        .bind(h.id.as_str())
        .execute(&pool)
        .await
        .expect("repoint");
    (s, pool, site.host())
}

/// Run one `monitor_tick` with the site in `mode`, first moving every
/// timestamp ten minutes back so the 60 s interval has elapsed.
async fn tick_as(
    s: &HostingService<MockAdapterPort>,
    pool: &SqlitePool,
    site: &TestSite,
    mode: SiteMode,
) {
    for sql in [
        "UPDATE monitor_samples SET sampled_at = sampled_at - 600",
        "UPDATE hostings SET monitor_last_alert_at = monitor_last_alert_at - 600 \
             WHERE monitor_last_alert_at IS NOT NULL",
    ] {
        sqlx::query(sql).execute(pool).await.expect("age");
    }
    site.set(mode);
    assert_eq!(s.monitor_tick().await.expect("tick"), 1, "{mode:?} sampled");
}

/// (kind, body) of every bell notification, oldest first.
async fn bells(pool: &SqlitePool) -> Vec<(String, String)> {
    sqlx::query_as("SELECT kind, body FROM notifications ORDER BY id")
        .fetch_all(pool)
        .await
        .expect("notifications")
}

/// The English pack, unmodified — what every install has until an
/// operator picks another language, and therefore what these tests
/// pin the built-in letters to.
fn en() -> LetterCatalog {
    LetterCatalog::new(LetterLang::En)
}

fn s3_target(name: &str) -> hyperion_types::S3BackupTarget {
    hyperion_types::S3BackupTarget {
        name: name.into(),
        endpoint: format!("https://{name}.example.net"),
        bucket: format!("bucket-{name}"),
        region: "eu-central-1".into(),
        access_key_id: "AKIA-test".into(),
        secret_access_key: "s3cret".into(),
        age_recipient: None,
        retention_daily: 7,
    }
}

fn bk_run(
    id: i64,
    state: &str,
    local: bool,
    remote_state: &str,
    no_offsite: bool,
) -> hyperion_state::backups::BackupRun {
    hyperion_state::backups::BackupRun {
        id,
        hosting_id: hyperion_types::HostingId("h".into()),
        target: "local".into(),
        started_at: 1000 - id,
        finished_at: Some(1000 - id),
        state: state.into(),
        archive_path: local.then(|| format!("/b/x.cz-{id}.tar.gz")),
        db_dump_path: None,
        bytes_total: 1,
        error_message: None,
        sha256_hex: String::new(),
        remote_blob_key: String::new(),
        remote_state: remote_state.into(),
        remote_error: String::new(),
        no_offsite,
        local_note: String::new(),
        s3_ok_targets: Vec::new(),
        purpose: String::new(),
        held: false,
    }
}

/// A worker set up from the master's settings sync: agent.toml plus
/// node-id.json in one temp dir.
async fn synced_worker(toml: &str) -> (HostingService<MockAdapterPort>, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tmp");
    let cfg = dir.path().join("agent.toml");
    std::fs::write(&cfg, toml).expect("write agent.toml");
    let state = dir.path().join("node-id.json");
    std::fs::write(&state, b"{}").expect("write node-id.json");
    let pool = open_memory().await.expect("memory db");
    let s = svc(pool, MockAdapterPort::new())
        .with_agent_config_path(cfg)
        .with_node_state_file(state);
    (s, dir)
}

fn sync_target(name: &str) -> hyperion_types::S3BackupTarget {
    hyperion_types::S3BackupTarget {
        name: name.into(),
        endpoint: "https://s3.example".into(),
        bucket: "bk".into(),
        region: "eu".into(),
        access_key_id: "AK".into(),
        secret_access_key: "SK".into(),
        age_recipient: None,
        retention_daily: 7,
    }
}

// ============================================================
//  Per-hosting HTTP brute-force switch (`[fail2ban]` scoped to
//  one site's login page) + the `[fail2ban]` settings editor.
// ============================================================

/// `happy_mocks` hands out one fixed UID and one fixed database name, so
/// a second `create` on the same pool trips `UNIQUE(uid)` /
/// `UNIQUE(engine, db_name)`. Tests that need several sites on one node
/// use this instead.
fn happy_mocks_many() -> MockAdapterPort {
    use std::sync::atomic::{AtomicU32, Ordering};
    let uid = AtomicU32::new(1042);
    let dbn = AtomicU32::new(1);
    let mut a = MockAdapterPort::new();
    a.expect_ensure_user()
        .returning(move |_, _| Ok(uid.fetch_add(1, Ordering::Relaxed)));
    a.expect_db_create().returning(move |_, _, _| {
        let n = dbn.fetch_add(1, Ordering::Relaxed);
        Ok(DbCredentials {
            engine: DbProvision::MariaDB,
            db_name: format!("lm_{n}"),
            db_user: format!("lm_u{n}"),
            password: "p".into(),
        })
    });
    a.expect_ensure_dirs().returning(|_, _, _, _| Ok(()));
    a.expect_fpm_ensure().returning(|_, _, _| Ok(()));
    a.expect_acme_issue().returning(|d, _| Ok(cert_for(d)));
    a.expect_nginx_write_vhost().returning(|_| Ok(()));
    a.expect_redis_is_available().returning(|| true);
    a
}

/// Write an nginx access.log where the HTTP scan looks for one — the
/// combined format it parses, `hits` wp-login POSTs from `ip`, stamped
/// now so they fall inside the scan window.
fn write_wp_login_flood(home_root: &std::path::Path, user: &str, domain: &str, ip: &str) {
    use chrono::{TimeZone, Utc};
    let dir = home_root.join(user).join(domain).join("logs");
    std::fs::create_dir_all(&dir).expect("logs dir");
    let ts = Utc
        .timestamp_opt(now_secs(), 0)
        .single()
        .expect("now")
        .format("%d/%b/%Y:%H:%M:%S +0000")
        .to_string();
    // One over the default threshold, so the flood is unambiguous.
    let line = format!("{ip} - - [{ts}] \"POST /wp-login.php HTTP/1.1\" 200 512 \"-\" \"curl\"\n");
    let body = line.repeat(Fail2banConfig::default().http_threshold as usize + 1);
    std::fs::write(dir.join("access.log"), body).expect("write access.log");
}

/// The site-attributed half of a scan, as sorted `(hosting id, ip)` —
/// sorted because `list()` promises no row order.
fn http_hits(intents: &[BanIntent]) -> Vec<(String, String)> {
    let mut v: Vec<(String, String)> = intents
        .iter()
        .filter_map(|i| i.site.as_ref().map(|s| (s.id.clone(), i.ip.clone())))
        .collect();
    v.sort();
    v
}

/// The node-wide half of a scan (ssh / ftp / mail), as sorted
/// `(ip, reason)`.
fn node_hits(intents: &[BanIntent]) -> Vec<(String, &'static str)> {
    let mut v: Vec<(String, &'static str)> = intents
        .iter()
        .filter(|i| i.site.is_none())
        .map(|i| (i.ip.clone(), i.reason))
        .collect();
    v.sort();
    v
}

fn engine(available: bool) -> hyperion_types::crs::ModsecStatus {
    hyperion_types::crs::ModsecStatus {
        module: available,
        crs: available,
        crs_version: "3.3.4".into(),
        ..Default::default()
    }
}

// ============================================================
//  A refused send is not a send. The customer letters (care
//  report, expiry warning) may never record delivery the relay
//  did not perform.
// ============================================================

/// An SMTP config every send fails against, with no relay running and no
/// network touched: `send_text` parses the From address before it opens a
/// connection, so a malformed one takes the exact `Err` branch a relay
/// that rejects the message takes — which is all these tests care about.
/// It is also a real operator mistake (a typo'd `from_address`).
fn refusing_relay() -> hyperion_adapters::email::EmailConfig {
    hyperion_adapters::email::EmailConfig {
        smtp_host: "127.0.0.1".into(),
        smtp_port: 25,
        smtp_user: String::new(),
        smtp_password: String::new(),
        from_address: "this is not a mailbox".into(),
        from_name: String::new(),
        security: "plain".into(),
    }
}

/// A site that buys a monthly report, whose period has been open for 40
/// days, on a node whose relay refuses everything.
async fn site_owing_a_care_report(
    pool: &SqlitePool,
) -> (HostingService<MockAdapterPort>, HostingDetail) {
    let s = svc(pool.clone(), happy_mocks()).with_email(Some(refusing_relay()), None);
    s.create(req("pece.cz")).await.expect("create");
    let sel = HostingSelector::Domain(Domain::parse("pece.cz").expect("parse"));
    let detail = s.get(sel.clone()).await.expect("get");
    // The customer's report address, kept apart from the expiry
    // `owner_email` on purpose.
    hyperion_state::hosting_kv::set(
        pool,
        detail.id.as_str(),
        CARE_REPORT_RECIPIENTS_KV_KEY,
        "zakaznik@pece.cz",
        1,
    )
    .await
    .expect("recipients");
    let _ = sel;
    // Bought 40 days ago ⇒ the first period is [activated_at, now) and
    // is more than one month wide, so the report is due.
    packages::activate(
        pool,
        &packages::NewActivation {
            report_omit: String::new(),
            valid_from: None,
            enforcement_started: true,
            hosting_id: detail.id.clone(),
            package_id: 1,
            package_name: "Péče".into(),
            check_items: String::new(),
            price_minor: None,
            price_currency: None,
            price_interval: None,
            features: PackageFeatures {
                report_cadence: ReportCadence::Monthly,
                ..Default::default()
            },
            next_billing_at: None,
            prior_state_json: None,
            letters_lang: String::new(),
        },
        now_secs() - 40 * 86_400,
    )
    .await
    .expect("activate");
    // Proof that the brute-force scanner has been watching the whole
    // time. Without it the report is entirely unmeasured and the tick
    // correctly declines to send anything — which would make this
    // fixture exercise that guard instead of the relay refusal it is
    // about.
    hyperion_state::hosting_kv::set(
        pool,
        detail.id.as_str(),
        FAIL2BAN_HTTP_SINCE_KV_KEY,
        &format!("{},{}", now_secs() - 41 * 86_400, now_secs()),
        now_secs(),
    )
    .await
    .expect("coverage stamp");
    (s, detail)
}

// ============================================================
//  SPF parser unit tests (no DNS — pure CIDR / string logic).
// ============================================================

// ============================================================
//  Migration bundle prune (pure-fs, no Service needed).
// ============================================================

// ============================================================
//  is_worker_node — drives the services_health "hide hyperion-web
//  as critical on workers" behavior.
// ============================================================

async fn svc_with_state_file(p: Option<std::path::PathBuf>) -> HostingService<MockAdapterPort> {
    let pool = open_memory().await.expect("memory db");
    let a = MockAdapterPort::new();
    let mut s = svc(pool, a);
    if let Some(path) = p {
        s = s.with_node_state_file(path);
    }
    s
}

/// Write an agent.toml carrying just a `[cluster] mode`.
async fn svc_with_mode(mode: Option<&str>) -> (HostingService<MockAdapterPort>, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tmp");
    let path = dir.path().join("agent.toml");
    let body = match mode {
        Some(m) => format!("[cluster]\nmode = \"{m}\"\n"),
        None => "[cluster]\nmaster_accepts_hostings = true\n".to_string(),
    };
    std::fs::write(&path, body).expect("write agent.toml");
    let pool = open_memory().await.expect("memory db");
    let s = svc(pool, MockAdapterPort::new()).with_agent_config_path(path);
    (s, dir)
}

async fn seed_web_user(
    s: &HostingService<MockAdapterPort>,
    name: &str,
    role: hyperion_state::web_users::WebRole,
) -> i64 {
    hyperion_state::web_users::insert(
        &s.pool,
        &hyperion_state::web_users::NewWebUser {
            username: name,
            email: &format!("{name}@x.cz"),
            password_hash: "$argon2id$x",
            role,
        },
        1,
    )
    .await
    .unwrap()
}

/// Mint an invite and enroll `candidate`, optionally publishing a
/// response-signing pubkey. Returns (effective_node_id, secret).
async fn enroll_node(
    s: &HostingService<MockAdapterPort>,
    candidate: &str,
    prior: Option<(&str, &str)>,
    resp_pubkey: Option<&str>,
) -> (String, String) {
    let mint = s.invite_create("n".into(), 3600).await.expect("invite");
    s.enroll_consume(
        mint.token.clone(),
        "1.2.3.4".into(),
        candidate.into(),
        "label".into(),
        "v1".into(),
        None,
        prior.map(|(id, _)| id.to_string()),
        prior.map(|(_, sec)| sec.to_string()),
        resp_pubkey.map(String::from),
        Default::default(),
    )
    .await
    .expect("enroll")
}

async fn pinned_key(s: &HostingService<MockAdapterPort>, node_id: &str) -> Option<String> {
    hyperion_state::nodes::get_by_node_id(&s.pool, node_id)
        .await
        .expect("get")
        .expect("row")
        .resp_pubkey
}

async fn pinned_tls(s: &HostingService<MockAdapterPort>, node_id: &str) -> Option<String> {
    hyperion_state::nodes::get_by_node_id(&s.pool, node_id)
        .await
        .expect("get")
        .expect("row")
        .tls_spki_pin
}

// ============================================================
//  expiry_warning_mail_with — the letter the customer actually
//  gets before we suspend their site. Pure, so the 30/7/1-day
//  variants are assertable without an SMTP relay. An empty
//  template is the built-in wording (see the editable-letter
//  block further down).
// ============================================================

/// 2026-09-01 00:00:00 UTC.
const EXP_TS: i64 = 1_788_220_800;

// ============================================================
//  Editable customer letters (care report + expiry warning).
//
//  Four properties, in order of how much they matter:
//   1. an operator who never touches a template gets today's
//      letter, byte for byte;
//   2. the default template we SHOW the operator reproduces
//      that same letter — otherwise the editor lies about
//      where they are starting from;
//   3. an unmeasured section stays unmeasured through a custom
//      letter (the placeholders are section STRINGS, so there
//      is no way to spend a number we never measured);
//   4. an unknown placeholder survives as literal text instead
//      of panicking or silently deleting a paragraph.
// ============================================================

/// 2026-06-01 00:00:00 UTC .. 2026-07-01 (half-open, 30 days).
const CARE_FROM: i64 = 1_780_272_000;
const CARE_TO: i64 = CARE_FROM + 30 * 86_400;

/// A report with five sections measured and UPTIME deliberately not —
/// the mixed case, which is the one a custom letter can get wrong.
fn mk_care_report() -> CareReport {
    let mut r = CareReport::empty(
        HostingId("h1".into()),
        "example.cz".into(),
        CARE_FROM,
        CARE_TO,
    );
    r.attacks_blocked = Some(12);
    r.updates_applied = Some(3);
    r.usage = Some(CareUsage {
        bw_in_bytes: Some(2_000_000),
        bw_out_bytes: 34_500_000,
        requests: 12_345,
        disk_peak_bytes: 1_200_000_000,
        days_counted: 30,
        days_in_period: 30,
    });
    r.uptime = None; // not monitored — on purpose
    r.backups = Some(CareBackups {
        taken: 30,
        failed: 1,
        last_success_at: Some(CARE_TO - 3_600),
    });
    r.integrity = Some(CareIntegrity {
        scanned_at: CARE_TO - 86_400,
        checksums_ran: true,
        malware_scan_ran: true,
        core_issues: 0,
        plugin_issues: 0,
        malware_hits: 0,
    });
    // A readable checklist with everything ticked — the ordinary case.
    // `None` here would mean the record could not be READ, which puts
    // "checks by hand" in the unmeasured disclosure and is a different
    // fixture from the one these tests want.
    r.service_work = Some(hyperion_types::package::CareServiceWork {
        done: hyperion_types::care_check::ServiceCheckItem::ALL
            .iter()
            .map(|i| i.as_str().to_string())
            .collect(),
        missing: Vec::new(),
        labels: Default::default(),
    });
    r
}

// ============================================================
//  count_profile_asset_refs — boundary handling so @asset:7
//  doesn't accidentally match @asset:70 / @asset:777.
// ============================================================

fn mk_profile(plugins: &str, themes: &str) -> hyperion_state::profiles::ProfileRow {
    hyperion_state::profiles::ProfileRow {
        wp_plugins: plugins.into(),
        wp_themes: themes.into(),
        ..Default::default()
    }
}

/// Mirrors the filter in `dig_records`. Kept beside the test rather than
/// exported, because the point is to pin the RULE — if the real one
/// changes shape, this test should be read again rather than silently
/// keep passing.
fn keeps(kind: &str, line: &str) -> bool {
    let l = line.trim();
    if l.is_empty() {
        return false;
    }
    if !matches!(kind, "A" | "AAAA") {
        return true;
    }
    match l.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(_)) => kind == "A",
        Ok(std::net::IpAddr::V6(_)) => kind == "AAAA",
        Err(_) => false,
    }
}

fn req(d: &str) -> HostingCreateReq {
    HostingCreateReq {
        domain: Domain::parse(d).expect("parse"),
        aliases: vec![],
        php_version: Some(PhpVersion::V8_3),
        database: Some(DbProvision::MariaDB),
        system_user: None,
        kind: "php".into(),
        proxy_upstream_url: None,
    }
}

fn cert_for(d: &str) -> CertInfo {
    CertInfo {
        domain: d.into(),
        sans: vec![],
        issuer: "letsencrypt".into(),
        not_after: 1_700_000_000,
        fingerprint_sha256: "deadbeef".into(),
    }
}

fn db_creds() -> DbCredentials {
    DbCredentials {
        engine: DbProvision::MariaDB,
        db_name: "lm_a".into(),
        db_user: "lm_u".into(),
        password: "p".into(),
    }
}

fn happy_mocks() -> MockAdapterPort {
    let mut a = MockAdapterPort::new();
    a.expect_ensure_user().returning(|_, _| Ok(1042));
    a.expect_ensure_dirs().returning(|_, _, _, _| Ok(()));
    a.expect_fpm_ensure().returning(|_, _, _| Ok(()));
    a.expect_db_create().returning(|_, _, _| Ok(db_creds()));
    a.expect_acme_issue().returning(|d, _| Ok(cert_for(d)));
    a.expect_nginx_write_vhost().returning(|_| Ok(()));
    // mockall ignores trait default impls — without an explicit
    // `expect`, calls to `redis_is_available` panic. Default-true
    // in tests so the Redis preflight in set_redis doesn't break
    // tests that don't care about the systemd-level check.
    a.expect_redis_is_available().returning(|| true);
    a
}

fn svc(pool: SqlitePool, a: MockAdapterPort) -> HostingService<MockAdapterPort> {
    let secrets_dir = tempfile::tempdir().expect("dir");
    let secrets = Arc::new(SecretsStore::new(secrets_dir.keep()));
    HostingService::new(pool, Arc::new(a), secrets)
}

fn suspend_mocks() -> MockAdapterPort {
    let mut a = happy_mocks();
    a.expect_nginx_apply_suspended().returning(|_, _, _| Ok(()));
    a.expect_fpm_delete().returning(|_, _| Ok(()));
    a.expect_db_lock().returning(|_, _| Ok(()));
    a.expect_linux_lock_login().returning(|_| Ok(()));
    a.expect_linux_login_expiry()
        .returning(|_| Ok(Some(String::new())));
    a.expect_linux_set_login_expiry().returning(|_, _| Ok(()));
    a.expect_kill_user_procs().returning(|_| Ok(()));
    a
}

fn resume_mocks() -> MockAdapterPort {
    let mut a = MockAdapterPort::new();
    a.expect_ensure_user().returning(|_, _| Ok(1042));
    a.expect_ensure_dirs().returning(|_, _, _, _| Ok(()));
    a.expect_fpm_ensure().returning(|_, _, _| Ok(()));
    a.expect_db_create().returning(|_, _, _| Ok(db_creds()));
    a.expect_acme_issue().returning(|d, _| Ok(cert_for(d)));
    a.expect_nginx_write_vhost().returning(|_| Ok(()));
    a.expect_nginx_apply_suspended().returning(|_, _, _| Ok(()));
    a.expect_fpm_delete().returning(|_, _| Ok(()));
    a.expect_db_lock().returning(|_, _| Ok(()));
    a.expect_linux_lock_login().returning(|_| Ok(()));
    a.expect_linux_login_expiry()
        .returning(|_| Ok(Some(String::new())));
    a.expect_linux_set_login_expiry().returning(|_, _| Ok(()));
    a.expect_kill_user_procs().returning(|_| Ok(()));
    a.expect_linux_unlock_login().returning(|_| Ok(()));
    a.expect_db_unlock().returning(|_, _| Ok(()));
    a.expect_apply_php_limits()
        .returning(|_, _, _, _, _, _, _| Ok(()));
    a
}

/// A stand-in for the shadow file's account-expiry column: every read and
/// write the service makes goes through this map, so a test can check
/// what an account ends up with, not just which calls were made.
type FakeShadow = std::sync::Arc<std::sync::Mutex<std::collections::BTreeMap<String, String>>>;

fn with_fake_shadow(mut a: MockAdapterPort, shadow: &FakeShadow) -> MockAdapterPort {
    let read = shadow.clone();
    a.expect_linux_login_expiry()
        .returning(move |login| Ok(read.lock().expect("lock").get(login).cloned()));
    let write = shadow.clone();
    a.expect_linux_set_login_expiry()
        .returning(move |login, value| {
            if let Some(v) = write.lock().expect("lock").get_mut(login) {
                *v = value.to_string();
            }
            Ok(())
        });
    a
}

/// Mocks for create + suspend + resume + trash + restore, with no
/// expectation on the logins themselves (the test adds the fake shadow).
fn offline_cycle_mocks() -> MockAdapterPort {
    let mut a = MockAdapterPort::new();
    a.expect_ensure_user().returning(|_, _| Ok(1042));
    a.expect_ensure_dirs().returning(|_, _, _, _| Ok(()));
    a.expect_fpm_ensure().returning(|_, _, _| Ok(()));
    a.expect_db_create().returning(|_, _, _| Ok(db_creds()));
    a.expect_acme_issue().returning(|d, _| Ok(cert_for(d)));
    a.expect_nginx_write_vhost().returning(|_| Ok(()));
    a.expect_redis_is_available().returning(|| true);
    a.expect_nginx_apply_suspended().returning(|_, _, _| Ok(()));
    a.expect_fpm_delete().returning(|_, _| Ok(()));
    a.expect_db_lock().returning(|_, _| Ok(()));
    a.expect_db_unlock().returning(|_, _| Ok(()));
    a.expect_kill_user_procs().returning(|_| Ok(()));
    a.expect_apply_php_limits()
        .returning(|_, _, _, _, _, _, _| Ok(()));
    a
}

async fn site_with_extra_login(
    s: &HostingService<MockAdapterPort>,
    pool: &sqlx::SqlitePool,
    shadow: &FakeShadow,
) -> HostingDetail {
    s.create(req("kos.cz")).await.expect("create");
    let detail = s
        .get(HostingSelector::Domain(
            Domain::parse("kos.cz").expect("parse"),
        ))
        .await
        .expect("get");
    hyperion_state::ftp_accounts::insert(
        pool,
        &detail.id,
        "web.kos.cz",
        &detail.root_dir,
        "",
        "kevin",
        now_secs(),
    )
    .await
    .expect("extra login");
    let mut sh = shadow.lock().expect("lock");
    sh.insert(detail.system_user.clone(), String::new());
    // An expiry the operator set on this login themselves.
    sh.insert("web.kos.cz".into(), "20500".into());
    drop(sh);
    detail
}

/// A second hosting on `a`'s system user, straight into the table.
async fn sibling_on_same_user(
    pool: &sqlx::SqlitePool,
    a: &HostingDetail,
    domain: &str,
) -> HostingId {
    let suid = hyperion_state::system_users::get_by_name(pool, &a.system_user)
        .await
        .expect("user row")
        .expect("present")
        .id;
    let id = HostingId::new_v7();
    hostings::insert(pool, &id, domain, suid, None, "/r", now_secs(), None)
        .await
        .expect("sibling");
    id
}

// ───────── set_vhost_options ─────────

fn vh_defaults() -> hyperion_types::VhostOptions {
    hyperion_types::VhostOptions::default()
}

// ============================================================
//  WordPress integrity scan. The feature exists because the
//  operator SELLS "regular malware scanning", so the thing worth
//  guarding is not the happy path — it's that a scan which could
//  not run never renders as a clean site.
// ============================================================

/// A core verification that actually ran and found nothing.
fn core_verified() -> integrity::CoreChecksums {
    integrity::CoreChecksums {
        checked: true,
        ..Default::default()
    }
}

/// A plugin verification that actually ran and found nothing.
fn plugins_verified() -> integrity::PluginChecksums {
    integrity::PluginChecksums {
        checked: true,
        ..Default::default()
    }
}

// ============================================================
//  Care packages — the paid entitlement layer.
//
//  What these guard is the difference between a package and a
//  label: that activating one really flips the features, that
//  cancelling puts back exactly what it changed and nothing
//  else, and that a paid feature switched off by hand comes
//  back on the next tick.
// ============================================================

/// `set_vhost_options` (the hardening path) drops the htpasswd file
/// whenever basic auth is off — which is every hosting in these tests.
fn package_mocks() -> MockAdapterPort {
    let mut a = happy_mocks();
    a.expect_nginx_delete_htpasswd().returning(|_| Ok(()));
    a
}

/// Two hostings in one test: `happy_mocks` hands out a fixed uid, which
/// the second `create` collides with on `system_users.uid`.
fn package_mocks_two_sites() -> MockAdapterPort {
    let mut a = MockAdapterPort::new();
    let next_uid = std::sync::atomic::AtomicU32::new(1042);
    a.expect_ensure_user()
        .returning(move |_, _| Ok(next_uid.fetch_add(1, std::sync::atomic::Ordering::Relaxed)));
    a.expect_ensure_dirs().returning(|_, _, _, _| Ok(()));
    a.expect_fpm_ensure().returning(|_, _, _| Ok(()));
    a.expect_acme_issue().returning(|d, _| Ok(cert_for(d)));
    a.expect_nginx_write_vhost().returning(|_| Ok(()));
    a.expect_redis_is_available().returning(|| true);
    a.expect_nginx_delete_htpasswd().returning(|_| Ok(()));
    a
}

/// …and a fixed database name, so the two-site test provisions none.
fn req_no_db(d: &str) -> HostingCreateReq {
    HostingCreateReq {
        database: None,
        ..req(d)
    }
}

fn care_input(name: &str, features: PackageFeatures) -> PackageInput {
    PackageInput {
        name: name.into(),
        price_minor: Some(49_000),
        price_currency: Some("Kč".into()),
        price_interval: Some("monthly".into()),
        features,
        ..Default::default()
    }
}

async fn kv_of(pool: &SqlitePool, hosting_id: &str, key: &str) -> Option<String> {
    hyperion_state::hosting_kv::get(pool, hosting_id, key)
        .await
        .expect("kv read")
}

async fn monitoring_on(pool: &SqlitePool, id: &HostingId) -> bool {
    hyperion_state::monitors::get(pool, id)
        .await
        .expect("monitor read")
        .expect("monitor row")
        .enabled
}

// ============================================================
//  WordPress updates — what the cluster page is told.
//
//  The page sorts sites into "needs you", "updating itself",
//  "couldn't check" and "up to date". Each of these guards one
//  way the node used to leave it guessing.
// ============================================================

fn wp_plugin(slug: &str, version: &str, latest: &str) -> hyperion_types::WpPlugin {
    hyperion_types::WpPlugin {
        slug: slug.into(),
        name: slug.into(),
        version: version.into(),
        status: "active".into(),
        update_available: !latest.is_empty(),
        latest_version: latest.into(),
        auto_update: false,
        auto_update_blocked: false,
        auto_update_block_reason: None,
    }
}

/// Mocks for a site whose plugin list is `plugins` on every scan, no
/// themes, and whose core is offered `core`.
fn wp_scan_mocks(
    plugins: Vec<hyperion_types::WpPlugin>,
    core: Vec<hyperion_types::WpCoreUpdate>,
) -> MockAdapterPort {
    let mut a = package_mocks();
    a.expect_wp_plugin_list()
        .returning(move |_, _| Ok((plugins.clone(), "6.5.3".into())));
    a.expect_wp_theme_list()
        .returning(|_, _| Ok((vec![], "6.5.3".into())));
    a.expect_wp_core_check_update()
        .returning(move |_, _| Ok(core.clone()));
    a
}

fn os_status(security: i64, since: i64, checked_at: i64) -> hyperion_types::OsUpdateStatus {
    hyperion_types::OsUpdateStatus {
        checked_at,
        index_refreshed_at: checked_at,
        security_count: security,
        security_pending_since: since,
        ..Default::default()
    }
}

/// A hosting plus the detail every package test needs.
///
/// `create` auto-enables uptime monitoring, so a brand-new site starts
/// with monitoring ON and everything else at its own default — the
/// tests that care about monitoring set it explicitly rather than
/// leaning on that.
async fn hosting_for_packages(s: &HostingService<MockAdapterPort>, domain: &str) -> HostingDetail {
    s.create(req(domain)).await.expect("create");
    s.get(HostingSelector::Domain(
        Domain::parse(domain).expect("parse"),
    ))
    .await
    .expect("get")
}

// ============================================================
//  Care-plan start date ("valid from") and report sections.
// ============================================================

fn omit_of(ids: &str) -> ReportOmit {
    ReportOmit::parse(ids)
}

fn carry_mocks() -> MockAdapterPort {
    // Several sites per test: each needs its own uid.
    let mut a = happy_mocks_many();
    a.expect_apply_php_limits()
        .returning(|_, _, _, _, _, _, _| Ok(()));
    a.expect_modsec_status()
        .returning(hyperion_types::crs::ModsecStatus::default);
    a.expect_nginx_write_htpasswd().returning(|_, _, _| Ok(()));
    a.expect_nginx_delete_htpasswd().returning(|_| Ok(()));
    a
}

/// Set up a source site with one of everything that should travel.
async fn carry_source(s: &HostingService<MockAdapterPort>, pool: &SqlitePool) -> HostingDetail {
    s.create(req("shop.cz")).await.expect("create");
    let sel = HostingSelector::Domain(Domain::parse("shop.cz").expect("parse"));
    let detail = s.get(sel.clone()).await.expect("get");
    let id = detail.id.as_str();

    let mut l = s.get_limits(sel.clone()).await.expect("limits");
    l.php_memory_mb = 768;
    l.php_max_children = 14;
    s.set_limits(sel.clone(), l).await.expect("limits");
    for (k, v) in [
        ("backup_at", "03:30"),
        ("backup_cadence", "daily"),
        ("php.mem_auto_max_mb", "1024"),
        ("care_service_checks", "{\"2026-10\":[\"updates\"]}"),
        ("dkim", "{\"selector\":\"h1\",\"enabled\":false}"),
        ("gitsync_webhook_secret", "s3cr3t"),
        ("gitsync_webhook", "1"),
        ("backup_last_run_at", "123"),
    ] {
        hyperion_state::hosting_kv::set(pool, id, k, v, 1)
            .await
            .expect("kv");
    }
    s.quota_set(sel.clone(), 0, 0, 0, 0, 0, "suspend")
        .await
        .expect("quota");

    let mut opts = detail.vhost_options.clone();
    opts.noindex = true;
    opts.force_https = true;
    opts.canonical_host = "www".into();
    opts.basic_auth_enabled = true;
    opts.basic_auth_user = "preview".into();
    opts.set_waf_level(hyperion_types::waf::WafLevel::Strict);
    hyperion_state::hostings::set_vhost_options(pool, &detail.id, &opts, Some("$2b$10$hash"), 1)
        .await
        .expect("vhost");

    let mut e = hyperion_types::HostingExpiry::defaults();
    e.expires_at = Some(now_secs() + 40 * 86_400);
    e.owner_email = Some("owner@shop.cz".into());
    s.set_expiry(sel.clone(), e).await.expect("expiry");
    s.monitor_set(
        sel.clone(),
        true,
        Some("/health".into()),
        Some(120),
        Some(4),
        Some("ops@shop.cz".into()),
        None,
        false,
        None,
    )
    .await
    .expect("monitor");
    let pid = profiles::insert(
        pool,
        &profiles::NewProfile {
            name: "Business".into(),
            ..Default::default()
        },
        1,
    )
    .await
    .expect("profile");
    profiles::upsert_apply(
        pool,
        &detail.id,
        Some(pid),
        Some(49_900),
        Some("CZK"),
        Some("monthly"),
        Some(1_900_000_000),
        None,
        None,
        1_700_000_000,
    )
    .await
    .expect("apply");
    profiles::set_price(
        pool,
        &detail.id,
        Some(39_900),
        Some("CZK"),
        Some("monthly"),
        Some(1_900_000_000),
        true,
        1_700_000_000,
    )
    .await
    .expect("price");
    hyperion_state::packages::activate(
        pool,
        &hyperion_state::packages::NewActivation {
            hosting_id: detail.id.clone(),
            package_id: 3,
            package_name: "Care Plus".into(),
            price_minor: Some(99_000),
            price_currency: Some("CZK".into()),
            price_interval: Some("monthly".into()),
            features: Default::default(),
            next_billing_at: Some(1_900_000_000),
            prior_state_json: Some("{}".into()),
            letters_lang: "cs".into(),
            check_items: String::new(),
            report_omit: String::new(),
            valid_from: None,
            enforcement_started: true,
        },
        1_700_000_100,
    )
    .await
    .expect("activate");
    s.get(sel).await.expect("get")
}

mod auth;
mod backups;
mod billing;
mod care_packages;
mod care_report;
mod certs;
mod cluster;
mod config;
mod dashboard;
mod firewall;
mod fs_health;
mod fs_util;
mod hosting_profiles;
mod jobs;
mod kv_expiry;
mod letters;
mod limits;
mod login_lock;
mod mail;
mod migration;
mod misc;
mod monitor;
mod net;
mod node_config;
mod nodes;
mod notify;
mod offsite;
mod os_updates;
mod permissions;
mod protection;
mod provision;
mod quota;
mod rollback;
mod scheduler;
mod site_config;
mod snapshots;
mod staging;
mod stats;
mod system;
mod trash;
mod users;
mod wp;
mod wp_assets;
mod wp_integrity;
mod wp_mail;
mod wp_updates;
