//! The scan pipeline with no panel in front of it, for `packaging/dev/sitescan-e2e.sh`:
//! real `systemd-run`, real wordpress.org, real MariaDB and real clamscan. What the
//! agent does between its worker jobs is repeated here in its plainest form.
//!
//! ```text
//! sitescan_e2e discover <root> <worker-exe>
//! sitescan_e2e scan <root> <scan-dir> <hosting-id> <delta|full> <worker-exe>
//! sitescan_e2e vendor <root> <scan-dir> <hosting-id> <db-user> <worker-exe>   (E2E_DB_PASSWORD)
//! sitescan_e2e clam <list-file> <vanish-path|-> <hosting-id=root>...
//! sitescan_e2e scan-worker
//! ```
//!
//! Every command prints one JSON document. `<worker-exe>` is whatever answers to
//! `scan-worker`: the real agent, this example, or a probe wrapped around either.

use std::collections::BTreeSet;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime};

use hyperion_adapters::backup::DbLogin;
use hyperion_adapters::integrity::{
    clamav_preflight, clamav_prepare, clamav_run, ClamFacts, ClamPreflight,
};
use hyperion_adapters::mariadb::{read_option, UPDATE_PLUGINS_OPTION, UPDATE_THEMES_OPTION};
use hyperion_adapters::sitescan::discover::Discovery;
use hyperion_adapters::sitescan::manifest::{
    fetch_wporg_manifest, wporg_slug_known, ComponentKind,
};
use hyperion_adapters::sitescan::runner::{
    prepare_scan_dirs, run_worker, worker_main, WorkerJob, WorkerReply, WORKER_ARG,
};
use hyperion_adapters::sitescan::scan::{ScanInput, ScanMode};
use hyperion_adapters::sitescan::vendor::{
    fetch_package, parse_update_transient, plan_downloads, read_wp_config_db, vendor_candidates,
};
use hyperion_types::HostingId;
use serde_json::{json, Value};

type Res<T> = Result<T, Box<dyn Error>>;

fn main() -> Res<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    if args.first() == Some(&WORKER_ARG) {
        std::process::exit(worker_main());
    }
    let run = tokio::runtime::Runtime::new()?;
    let out = run.block_on(async {
        match args.as_slice() {
            ["discover", root, exe] => discover(root, exe).await,
            ["scan", root, dir, id, mode, exe] => scan(root, dir, id, mode, exe).await,
            ["vendor", root, dir, id, user, exe] => vendor(root, dir, id, user, exe).await,
            ["clam", list, vanish, sites @ ..] => clam(list, vanish, sites).await,
            _ => Err("usage: see the top of sitescan_e2e.rs".into()),
        }
    })?;
    println!("{out}");
    Ok(())
}

async fn discovery_of(root: &str, exe: &str) -> Res<Result<Discovery, WorkerReply>> {
    let job = WorkerJob::Discover { root: root.into() };
    Ok(match run_worker(&job, Path::new(exe)).await? {
        WorkerReply::Discovery(d) => Ok(d),
        other => Err(other),
    })
}

async fn discover(root: &str, exe: &str) -> Res<Value> {
    let job = WorkerJob::Discover { root: root.into() };
    Ok(serde_json::to_value(
        run_worker(&job, Path::new(exe)).await?,
    )?)
}

/// What the agent's manifest pass finds out, with no budget: which slugs
/// wordpress.org knows, and why anything couldn't be asked.
async fn manifests(d: &Discovery, dir: &Path) -> (Option<BTreeSet<String>>, Vec<String>) {
    let mut known = Some(BTreeSet::new());
    let mut reasons = Vec::new();
    for c in &d.components {
        let is_core = c.key.kind == ComponentKind::Core;
        let answer = match fetch_wporg_manifest(&c.key, dir).await {
            Ok(a) => a,
            Err(e) => {
                reasons.push(format!("{}: {e}", c.key.slug));
                known = None;
                continue;
            }
        };
        if is_core {
            continue;
        }
        let is_known = if answer.is_some() {
            true
        } else if c.is_child_theme || c.key.version.is_empty() {
            continue;
        } else {
            match wporg_slug_known(c.key.kind, &c.key.slug, dir).await {
                Ok(k) => k,
                Err(e) => {
                    reasons.push(format!("{}: {e}", c.key.slug));
                    known = None;
                    continue;
                }
            }
        };
        if let (true, Some(set)) = (is_known, known.as_mut()) {
            set.insert(c.key.slug.clone());
        }
    }
    (known, reasons)
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

async fn scan(root: &str, dir: &str, id: &str, mode: &str, exe: &str) -> Res<Value> {
    let dir = PathBuf::from(dir);
    prepare_scan_dirs(&dir)?;
    let manifests_dir = dir.join("manifests");
    let total = Instant::now();
    let discovery = match discovery_of(root, exe).await? {
        Ok(d) => d,
        Err(reply) => return Ok(json!({ "reply": reply })),
    };
    let (known, reasons) = manifests(&discovery, &manifests_dir).await;
    let job = WorkerJob::Scan(ScanInput {
        root: root.into(),
        discovery: discovery.clone(),
        manifests_dir,
        baseline_path: dir.join("baselines").join(id),
        mode: if mode == "full" {
            ScanMode::FullRehash
        } else {
            ScanMode::Delta
        },
        now: unix_now(),
        wporg_known_slugs: known.clone(),
        accepted: None,
        own_expected: Default::default(),
        own_files_since: 0,
        trusted: Default::default(),
        carried_rels: Vec::new(),
    });
    let started = Instant::now();
    let reply = run_worker(&job, Path::new(exe)).await?;
    Ok(json!({
        "reply": reply,
        "discovery": discovery,
        "known_slugs": known,
        "manifest_problems": reasons,
        "scan_wall_s": started.elapsed().as_secs_f64(),
        "total_wall_s": total.elapsed().as_secs_f64(),
    }))
}

/// The vendor pass for one site: its transients read as its own login, the plan,
/// the downloads. A URL can hold a licence key, so none is printed.
async fn vendor(root: &str, dir: &str, id: &str, user: &str, exe: &str) -> Res<Value> {
    let password = std::env::var("E2E_DB_PASSWORD")?;
    let manifests_dir = PathBuf::from(dir).join("manifests");
    prepare_scan_dirs(Path::new(dir))?;
    let discovery = match discovery_of(root, exe).await? {
        Ok(d) => d,
        Err(reply) => return Ok(json!({ "reply": reply })),
    };
    let (known, _) = manifests(&discovery, &manifests_dir).await;
    let known = known.ok_or("wordpress.org did not answer for every slug")?;
    let candidates = vendor_candidates(&discovery, &known);
    let (db, prefix) = read_wp_config_db(Path::new(root)).ok_or("no database in wp-config.php")?;
    let login = DbLogin {
        user,
        password: &password,
    };
    let mut refs = Vec::new();
    for (option, kind) in [
        (UPDATE_PLUGINS_OPTION, ComponentKind::Plugin),
        (UPDATE_THEMES_OPTION, ComponentKind::Theme),
    ] {
        if let Some(value) = read_option(&db, &prefix, option, &login).await? {
            refs.extend(parse_update_transient(&value, kind));
        }
    }
    let refs_found = refs.len();
    let plan = plan_downloads(
        refs,
        &candidates,
        &BTreeSet::new(),
        id,
        &manifests_dir,
        SystemTime::now(),
    );
    let mut fetched = Vec::new();
    for p in &plan.fetch {
        let result = fetch_package(p, id, &manifests_dir).await;
        fetched.push(json!({
            "slug": p.slug,
            "version": p.version,
            "verifies_today": p.verifies_today,
            "result": format!("{result:?}"),
        }));
    }
    Ok(json!({
        "candidates": candidates.iter().map(|k| &k.slug).collect::<Vec<_>>(),
        "refs_found": refs_found,
        "fetched": fetched,
        "unknown_hosts": plan.unknown_hosts,
    }))
}

/// One weekly ClamAV pass, the way the tick starts it. `vanish` is deleted between
/// the listing and the scan.
async fn clam(list: &str, vanish: &str, sites: &[&str]) -> Res<Value> {
    let facts = ClamFacts::read();
    let go = clamav_preflight(
        facts.installed,
        facts.mem_available,
        facts.db_present,
        0,
        unix_now(),
    );
    if go != ClamPreflight::Run {
        return Ok(json!({ "preflight": format!("{go:?}") }));
    }
    let mut roots = Vec::new();
    for site in sites {
        let (id, root) = site.split_once('=').ok_or("expected <hosting-id>=<root>")?;
        roots.push((HostingId::from(id.to_string()), root.to_string()));
    }
    let plan = clamav_prepare(&roots, Path::new(list))?;
    let listed: Vec<String> = plan.sites.iter().map(|s| format!("{s:?}")).collect();
    if vanish != "-" {
        std::fs::remove_file(vanish)?;
    }
    let started = Instant::now();
    let sweep = clamav_run(plan).await?;
    Ok(json!({
        "preflight": "Run",
        "listed": listed,
        "end": format!("{:?}", sweep.end),
        "hits": sweep.hits,
        "vanished": sweep.vanished,
        "unread": sweep.unread.iter().map(|h| h.to_string()).collect::<Vec<_>>(),
        "dropped_hits": sweep.dropped_hits,
        "wall_s": started.elapsed().as_secs_f64(),
    }))
}
