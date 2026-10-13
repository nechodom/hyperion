//! Keeps the WordPress plugin library on every server.
//!
//! The library (plugin and theme ZIPs, `/profiles/wp-assets`) is uploaded to
//! the master, and wp-cli installs a ZIP from the disk of the server the site
//! lives on. A worker used to have no copy at all, so "Install from library"
//! on a worker's site, a profile with `@asset:<id>` lines applied there, and
//! library picks on the test-site form all ended in "not found".
//!
//! Each worker now holds a mirror of the master's library under the SAME ids
//! (`WpAssetMirror`). Two paths keep it current:
//!
//! * **Before use** — [`crate::dispatcher::dispatch_to_node`] asks
//!   [`asset_ids_needed`] which library items a request installs, and
//!   [`ensure_on_node`] copies the missing or outdated ones first. This is
//!   the guarantee: an install never runs against a stale copy.
//! * **After a change** — upload, replace and delete re-sync every worker in
//!   the background ([`sync_all_in_background`]), and a slow periodic pass
//!   ([`spawn`]) catches a node that was offline at the time. This is what
//!   makes the library "already there" on a new server.
//!
//! The master is the only writer. A worker row the master doesn't have is
//! removed on a full sync, so `@asset:<id>` can never mean two different
//! files on two servers.

use crate::state::SharedState;
use hyperion_rpc::codec::{Request, Response};
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

/// How often every worker is reconciled when nothing triggered a sync.
const PERIODIC_SECS: u64 = 30 * 60;
/// Wait after start before the first periodic pass — the agent and the
/// node list need a moment.
const FIRST_PASS_DELAY_SECS: u64 = 90;

/// Library item ids `req` will install from, when it is sent to a worker.
/// Empty for everything else, which is nearly every request.
pub fn asset_ids_needed(req: &Request) -> Vec<i64> {
    match req {
        Request::WpInstallFromAsset { asset_id, .. } => vec![*asset_id],
        Request::ProfileWpItemInstall { line, .. } => asset_ids_in(line),
        // With `skip_wp_items` the caller installs line by line through
        // ProfileWpItemInstall above, so nothing is read from the library here.
        Request::ProfileApply {
            profile: Some(p),
            skip_wp_items: false,
            ..
        } => {
            let mut ids = asset_ids_in(&p.wp_plugins);
            for id in asset_ids_in(&p.wp_themes) {
                if !ids.contains(&id) {
                    ids.push(id);
                }
            }
            ids
        }
        _ => Vec::new(),
    }
}

/// `@asset:<id>` references in a profile list (one item per line, `!` =
/// activate, `#` starts a comment). Same reading the agent applies.
fn asset_ids_in(text: &str) -> Vec<i64> {
    let mut ids = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        let Some(rest) = line.strip_prefix("@asset:") else {
            continue;
        };
        let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
        if let Ok(id) = digits.parse::<i64>() {
            if id > 0 && !ids.contains(&id) {
                ids.push(id);
            }
        }
    }
    ids
}

/// One lock per worker: a bulk install to twenty sites on one server, or a
/// periodic pass that overlaps a create, must copy a 50 MB ZIP once, not
/// twenty times in parallel. The second caller finds it already there.
fn node_lock(node_id: &str) -> Arc<tokio::sync::Mutex<()>> {
    static LOCKS: OnceLock<std::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>> =
        OnceLock::new();
    let mut map = LOCKS
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    map.entry(node_id.to_string()).or_default().clone()
}

/// What a sync changed on one worker.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SyncReport {
    pub copied: usize,
    pub removed: usize,
}

/// The master's library, id → recorded hash.
async fn master_library(
    state: &SharedState,
) -> Result<Vec<hyperion_types::WpAssetSummary>, String> {
    match hyperion_rpc_client::call(&state.agent_socket, Request::WpAssetList).await {
        Ok(Response::WpAssetList(v)) => Ok(v),
        Ok(Response::Error(e)) => Err(format!("reading the library: {e}")),
        Ok(_) => Err("reading the library: unexpected response".into()),
        Err(e) => Err(format!("reading the library: {e}")),
    }
}

/// The worker's copy, id → hash.
async fn node_library(state: &SharedState, node_id: &str) -> Result<HashMap<i64, String>, String> {
    match crate::dispatcher::dispatch_remote_unchecked(state, node_id, Request::WpAssetList).await {
        Ok(Response::WpAssetList(v)) => Ok(v.into_iter().map(|a| (a.id, a.sha256)).collect()),
        Ok(Response::Error(e)) => Err(e.to_string()),
        Ok(_) => Err("unexpected response to WpAssetList".into()),
        Err(e) => Err(e.to_string()),
    }
}

/// Read one item off the master and store it on the worker.
async fn copy_one(state: &SharedState, node_id: &str, id: i64) -> Result<(), String> {
    let read = hyperion_rpc_client::call(&state.agent_socket, Request::WpAssetRead { id }).await;
    let req = match read {
        Ok(Response::WpAssetRead {
            id,
            kind,
            original_name,
            sha256,
            uploaded_at,
            uploaded_by,
            bytes_b64,
        }) => Request::WpAssetMirror {
            id,
            kind,
            original_name,
            sha256,
            uploaded_at,
            uploaded_by,
            bytes_b64,
        },
        Ok(Response::Error(e)) => return Err(e.to_string()),
        Ok(_) => return Err("unexpected response to WpAssetRead".into()),
        Err(e) => return Err(e.to_string()),
    };
    match crate::dispatcher::dispatch_remote_unchecked(state, node_id, req).await {
        Ok(Response::WpAssetMirror) => Ok(()),
        Ok(Response::Error(e)) => Err(e.to_string()),
        Ok(_) => Err("unexpected response to WpAssetMirror".into()),
        // An agent from before the mirror can't decode the request at all.
        Err(e) => Err(format!(
            "{e} — if this server runs an older Hyperion, update it first"
        )),
    }
}

/// Make sure the worker holds the master's current copy of each of `ids`.
/// Costs one list call when it already does. Errors name the item and say
/// what to do, for the operator who just clicked "install".
pub async fn ensure_on_node(state: &SharedState, node_id: &str, ids: &[i64]) -> Result<(), String> {
    let lock = node_lock(node_id);
    let _guard = lock.lock().await;
    let master = master_library(state).await?;
    let have = node_library(state, node_id)
        .await
        .map_err(|e| format!("couldn't read the plugin library on that server: {e}"))?;
    for id in ids {
        let Some(item) = master.iter().find(|a| a.id == *id) else {
            // Let the node answer with its own "not found" — the request
            // goes through and fails the same way it would on the master.
            continue;
        };
        if have
            .get(id)
            .is_some_and(|h| h.eq_ignore_ascii_case(&item.sha256))
        {
            continue;
        }
        copy_one(state, node_id, *id).await.map_err(|e| {
            format!(
                "couldn't copy \"{}\" from the plugin library to that server: {e}",
                item.original_name
            )
        })?;
        tracing::info!(node = node_id, asset_id = id, "wp library: copied to node");
    }
    Ok(())
}

/// Bring one worker's library in line with the master's: copy what is
/// missing or changed, remove what the master no longer has.
pub async fn sync_node(state: &SharedState, node_id: &str) -> Result<SyncReport, String> {
    let lock = node_lock(node_id);
    let _guard = lock.lock().await;
    let master = master_library(state).await?;
    let have = node_library(state, node_id).await?;
    let mut report = SyncReport::default();
    let mut errors = Vec::new();
    for item in &master {
        if have
            .get(&item.id)
            .is_some_and(|h| h.eq_ignore_ascii_case(&item.sha256))
        {
            continue;
        }
        match copy_one(state, node_id, item.id).await {
            Ok(()) => report.copied += 1,
            Err(e) => errors.push(format!("{}: {e}", item.original_name)),
        }
    }
    for id in have.keys() {
        if master.iter().any(|a| a.id == *id) {
            continue;
        }
        match crate::dispatcher::dispatch_remote_unchecked(
            state,
            node_id,
            Request::WpAssetDelete { id: *id },
        )
        .await
        {
            Ok(Response::WpAssetDelete) => report.removed += 1,
            Ok(Response::Error(e)) => errors.push(format!("remove item {id}: {e}")),
            Ok(_) => errors.push(format!("remove item {id}: unexpected response")),
            Err(e) => errors.push(format!("remove item {id}: {e}")),
        }
    }
    if errors.is_empty() {
        Ok(report)
    } else {
        Err(errors.join("; "))
    }
}

/// Sync every enrolled worker, one after another (a full first copy can be
/// hundreds of megabytes; there is no hurry). Logs, never fails.
pub async fn sync_all(state: &SharedState) {
    if state.deployment_mode.read().await.as_str() != "master" {
        return;
    }
    let nodes = match crate::handlers::hostings::fetch_remote_nodes(state).await {
        Ok(n) => n,
        Err(e) => {
            tracing::warn!(error = %e, "wp library sync: node list unavailable");
            return;
        }
    };
    for n in nodes {
        match sync_node(state, &n.node_id).await {
            Ok(r) if r == SyncReport::default() => {}
            Ok(r) => tracing::info!(
                node = %n.label,
                copied = r.copied,
                removed = r.removed,
                "wp library: synced to node"
            ),
            Err(e) => tracing::warn!(node = %n.label, error = %e, "wp library: sync failed"),
        }
    }
}

/// Re-sync every worker without holding up the request that changed the
/// library.
pub fn sync_all_in_background(state: SharedState) {
    tokio::spawn(async move { sync_all(&state).await });
}

/// The slow periodic pass, for workers that were offline when the library
/// changed (or enrolled since).
pub fn spawn(state: SharedState) {
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(FIRST_PASS_DELAY_SECS)).await;
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(PERIODIC_SECS));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            sync_all(&state).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyperion_rpc::HostingSelector;

    fn sel() -> HostingSelector {
        HostingSelector::Id(hyperion_types::HostingId("h".into()))
    }

    #[test]
    fn reads_asset_ids_the_way_profiles_write_them() {
        let text =
            "akismet!\n@asset:7\n@asset:12!   # client plugin\n# @asset:99\n@asset:7\n\n@asset:x\n";
        assert_eq!(asset_ids_in(text), vec![7, 12]);
    }

    #[test]
    fn only_library_installs_need_the_library() {
        assert_eq!(
            asset_ids_needed(&Request::WpInstallFromAsset {
                sel: sel(),
                asset_id: 5,
                activate: true,
            }),
            vec![5]
        );
        assert_eq!(
            asset_ids_needed(&Request::ProfileWpItemInstall {
                sel: sel(),
                item_kind: "plugin".into(),
                line: "@asset:3!".into(),
            }),
            vec![3]
        );
        assert!(asset_ids_needed(&Request::ProfileWpItemInstall {
            sel: sel(),
            item_kind: "plugin".into(),
            line: "akismet".into(),
        })
        .is_empty());
        assert!(asset_ids_needed(&Request::WpAssetList).is_empty());
    }

    #[test]
    fn profile_apply_needs_its_assets_unless_items_go_one_by_one() {
        let mut profile = crate::handlers::profiles::blank_profile();
        profile.wp_plugins = "@asset:4!\nakismet".into();
        profile.wp_themes = "@asset:9\n@asset:4".into();
        let req = |skip| Request::ProfileApply {
            sel: sel(),
            profile_id: 1,
            skip_wp_items: skip,
            profile: Some(profile.clone()),
        };
        assert_eq!(asset_ids_needed(&req(false)), vec![4, 9]);
        assert!(asset_ids_needed(&req(true)).is_empty());
    }
}
