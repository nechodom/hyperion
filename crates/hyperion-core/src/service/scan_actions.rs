//! What an operator can do about a file the scan reported: move it to quarantine,
//! put it back, or vouch for it.
//!
//! A form says which file, so nothing from it is believed: the path and hash must
//! name an item in the stored result, which is what the scan found in this
//! hosting's own docroot. What moves the file is in
//! [`hyperion_adapters::sitescan::quarantine`], which checks all of it again against
//! the disk. Who may ask is the web layer's: these requests come over the agent's
//! own socket or the signed node channel.

use super::*;
use hyperion_adapters::sitescan::quarantine::{
    valid_id, QuarantineRequest, RestoreRequest, CHANGED_SINCE_SCAN,
};
use hyperion_types::{
    FindingKind, QuarantineList, QuarantinedFile, SiteFileFinding, WpIntegrityScanResult,
};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// `hosting_kv` key: the files someone vouched for, as JSON path -> hex hash. The
/// one place this is kept. It travels with a Copy, since the paths are relative to
/// the docroot and the content comes along.
pub(super) const SCAN_TRUST_KV_KEY: &str = "scan_trust";
/// Entries a site's trust list may hold.
const TRUST_CAP: usize = 5000;
/// Quarantined files one reply lists.
const QUARANTINE_LIST_CAP: usize = 50;
/// A scan records no longer name.
const MAX_TRUST_PATH_BYTES: usize = 1024;
/// Files named per audit row of a bulk trust.
const TRUST_AUDIT_CHUNK: usize = 100;
/// How much of a path from a form goes into a row about refusing it.
const AUDITED_PATH_BYTES: usize = 1024;

fn stale() -> RpcError {
    RpcError::Conflict {
        message: CHANGED_SINCE_SCAN.to_string(),
    }
}

fn refuse(message: &str) -> RpcError {
    RpcError::Conflict {
        message: message.to_string(),
    }
}

/// The item a form names. Both have to match, so a stale card or a made-up path
/// gets no further than this.
fn item_named<'a>(
    result: &'a WpIntegrityScanResult,
    rel: &str,
    sha256: &str,
) -> Result<&'a SiteFileFinding, RpcError> {
    result
        .findings
        .iter()
        .chain(&result.review)
        .find(|f| f.rel == rel && f.sha256 == sha256)
        .ok_or_else(stale)
}

/// Says why, for each thing `SiteFileFinding::is_actionable` rules out, so a form
/// that gets past the card gets the same answer.
fn check_one_file(item: &SiteFileFinding) -> Result<(), RpcError> {
    if item.is_actionable() {
        return Ok(());
    }
    Err(refuse(
        "this item doesn't name one file that was read, so it can't be acted on from here",
    ))
}

fn check_trustable(item: &SiteFileFinding) -> Result<(), RpcError> {
    check_one_file(item)?;
    if item.is_comparison() {
        return Err(refuse(
            "this file fails its comparison with the official copy, so it can't be trusted; it can be repaired, reinstalled or quarantined",
        ));
    }
    Ok(())
}

fn check_movable(item: &SiteFileFinding) -> Result<(), RpcError> {
    if matches!(
        item.kind,
        FindingKind::CoreMissing | FindingKind::UpstreamMissing
    ) {
        return Err(refuse("this file is missing, so there's nothing to move"));
    }
    check_one_file(item)?;
    if item.symlink {
        return Err(refuse(
            "this is a symlink, so it isn't moved; remove it over SFTP",
        ));
    }
    if !item.can_quarantine() {
        return Err(refuse(
            "wp-config.php holds the site's database password and the site can't load without it, so it isn't moved; fix it by hand over SFTP",
        ));
    }
    Ok(())
}

/// A file moved or put back is off the card: its item, and its line on a core or
/// component list. What ClamAV said about it is the caller's: that goes with the
/// file and comes back with it.
fn drop_file(result: &mut WpIntegrityScanResult, rel: &str) {
    let item = result
        .findings
        .iter()
        .chain(&result.review)
        .find(|f| f.rel == rel)
        .cloned();
    result.findings.retain(|f| f.rel != rel);
    result.review.retain(|f| f.rel != rel);
    result.core_modified.retain(|p| p != rel);
    result.core_unexpected.retain(|p| p != rel);
    result.core_missing.retain(|p| p != rel);
    if let Some(item) = item {
        for list in [&mut result.plugins_failed, &mut result.themes_failed] {
            for component in list.iter_mut() {
                let slug = component.slug.clone();
                component.issues.retain(|i| !item.is_issue(&slug, &i.path));
            }
            list.retain(|c| !c.issues.is_empty());
        }
    }
    result.core_ok =
        result.wp_cli_ok && result.core_modified.is_empty() && result.core_unexpected.is_empty();
}

/// Trust speaks for the items it matched and nothing else. A comparison at the same
/// path is the manifest's to clear, and a ClamAV hit is ClamAV's.
fn drop_trusted(result: &mut WpIntegrityScanResult, rel: &str, sha256: &str) {
    let matched = |f: &SiteFileFinding| f.rel == rel && f.sha256 == sha256 && !f.is_comparison();
    result.findings.retain(|f| !matched(f));
    result.review.retain(|f| !matched(f));
}

/// Is this a path a scan could have reported? Relative, every step a real name, and
/// no longer than a scan records. What it opens is still checked again on the way.
fn plausible_rel(rel: &str) -> bool {
    !rel.is_empty()
        && rel.len() <= MAX_TRUST_PATH_BYTES
        && !rel.contains('\0')
        && rel
            .split('/')
            .all(|c| !c.is_empty() && c != "." && c != "..")
}

/// A carried trust list as this node will store it: what could be a scan's entries,
/// up to the cap, hashes in the form a scan writes them. A bundle is a file someone
/// could have edited, and this list is what stops a file being flagged. Returns the
/// JSON, how many were kept and how many weren't.
pub(super) fn clean_carried_trust(json: &str) -> (String, usize, usize) {
    let parsed: BTreeMap<String, serde_json::Value> =
        serde_json::from_str(json).unwrap_or_default();
    let total = parsed.len();
    let clean: BTreeMap<String, String> = parsed
        .into_iter()
        .filter(|(rel, _)| plausible_rel(rel))
        .filter_map(|(rel, hash)| Some((rel, hex::encode(decode_hash(hash.as_str()?)?))))
        .take(TRUST_CAP)
        .collect();
    let kept = clean.len();
    (
        serde_json::to_string(&clean).unwrap_or_default(),
        kept,
        total - kept,
    )
}

fn decode_hash(hex_hash: &str) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    hex::decode_to_slice(hex_hash, &mut out).ok()?;
    Some(out)
}

fn parse_trust(json: &str) -> BTreeMap<String, String> {
    serde_json::from_str(json).unwrap_or_default()
}

/// Who an audit row names. `hctl` and an older panel send nobody.
fn actor_label(actor: &str) -> &str {
    if actor.is_empty() {
        "agent"
    } else {
        actor
    }
}

/// `"ok"`, or `"refused"`: someone asked, and the row says what for.
fn outcome_of<T>(r: &Result<T, RpcError>) -> &'static str {
    if r.is_ok() {
        "ok"
    } else {
        "refused"
    }
}

/// A path from a form, fit for a row: bounded, and JSON's escaping keeps the rest
/// of what a tenant or a form can put in one from reaching the log as itself.
fn audited_path(rel: &str) -> String {
    let mut out = rel.to_string();
    clip(&mut out, AUDITED_PATH_BYTES);
    out
}

impl<A: AdapterPort + 'static> HostingService<A> {
    /// A hosting whose files can be acted on. A trashed or half-made one's aren't
    /// where the record says.
    async fn scan_action_target(&self, sel: HostingSelector) -> Result<HostingDetail, RpcError> {
        let detail = self.get(sel).await?;
        if !matches!(detail.state, HostingState::Active | HostingState::Suspended) {
            return Err(RpcError::Conflict {
                message: "this hosting's files can't be changed in its current state".into(),
            });
        }
        Ok(detail)
    }

    async fn scan_action_record(&self, hosting_id: &str) -> Result<StoredIntegrityScan, RpcError> {
        self.integrity_record(hosting_id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("integrity record: {e}")))?
            .ok_or_else(stale)
    }

    /// The file is gone from the card right away, its ClamAV hits go with it or come
    /// back with it, and a scan is asked for to say what is true now. Until it does
    /// the record is marked as not being a scan's.
    async fn after_file_action(
        &self,
        detail: &HostingDetail,
        change: impl FnOnce(&mut StoredIntegrityScan),
    ) {
        let id = detail.id.as_str();
        {
            let _record = self.site_scan.record.lock().await;
            match self.integrity_record(id).await {
                Ok(Some(mut rec)) => {
                    change(&mut rec);
                    rec.result.awaiting_rescan = true;
                    self.set_stored_integrity_scan(id, &rec).await;
                }
                Ok(None) => {}
                Err(e) => tracing::warn!(error = %e, "site scan: record not updated"),
            }
        }
        self.request_rescan(id).await;
    }

    /// The action happened whatever comes of this, so a failure is only logged.
    async fn request_rescan(&self, hosting_id: &str) {
        let now = now_secs();
        if let Err(e) = hyperion_state::hosting_kv::set(
            &self.pool,
            hosting_id,
            SCAN_REQUESTED_KV_KEY,
            &now.to_string(),
            now,
        )
        .await
        {
            tracing::warn!(error = %e, "site scan: re-scan not requested");
        }
        self.site_scan.wake.notify_one();
    }

    /// Move one reported file to quarantine.
    pub async fn scan_file_quarantine(
        &self,
        sel: HostingSelector,
        rel: String,
        sha256: String,
        actor: String,
    ) -> Result<WpIntegrityScanResult, RpcError> {
        let detail = self.scan_action_target(sel).await?;
        let done = self.quarantine_named(&detail, &rel, &sha256).await;
        let mut payload = serde_json::json!({ "path": audited_path(&rel), "hash": sha256 });
        if let Err(e) = &done {
            payload["reason"] = e.to_string().into();
        }
        self.append_audit_as(
            0,
            actor_label(&actor),
            "wp.integrity.quarantine",
            Some(detail.id.as_str()),
            &payload.to_string(),
            outcome_of(&done),
        )
        .await;
        let file = done?;
        self.after_file_action(&detail, |rec| {
            drop_file(&mut rec.result, &rel);
            // Only what the held record has: a hit a ClamAV pass added since stays.
            rec.result.malware.retain(|m| !file.malware.contains(m));
        })
        .await;
        self.wp_integrity_stored(HostingSelector::Id(detail.id))
            .await
    }

    async fn quarantine_named(
        &self,
        detail: &HostingDetail,
        rel: &str,
        sha256: &str,
    ) -> Result<QuarantinedFile, RpcError> {
        let rec = self.scan_action_record(detail.id.as_str()).await?;
        let item = item_named(&rec.result, rel, sha256)?;
        check_movable(item)?;
        let path = format!("{}/{rel}", detail.root_dir);
        let req = QuarantineRequest {
            root: PathBuf::from(&detail.root_dir),
            quarantine_dir: PathBuf::from(&self.paths.quarantine_dir),
            hosting_id: detail.id.as_str().to_string(),
            rel: rel.to_string(),
            sha256: sha256.to_string(),
            kind: item.kind,
            rule_id: item.rule_id.clone(),
            now: now_secs(),
            malware: rec
                .result
                .malware
                .iter()
                .filter(|m| m.path == path)
                .cloned()
                .collect(),
        };
        Ok(self.adapters.site_scan_quarantine(req).await?)
    }

    /// Put a quarantined file back. `id` comes from a form too: it is one random
    /// name in this hosting's own folder or it is nothing.
    pub async fn scan_file_restore(
        &self,
        sel: HostingSelector,
        id: String,
        actor: String,
    ) -> Result<WpIntegrityScanResult, RpcError> {
        let detail = self.scan_action_target(sel).await?;
        let done = if valid_id(&id) {
            self.adapters
                .site_scan_restore(RestoreRequest {
                    root: PathBuf::from(&detail.root_dir),
                    quarantine_dir: PathBuf::from(&self.paths.quarantine_dir),
                    hosting_id: detail.id.as_str().to_string(),
                    id: id.clone(),
                })
                .await
                .map_err(RpcError::from)
        } else {
            Err(refuse("this file is no longer in quarantine"))
        };
        let payload = match &done {
            Ok(file) => serde_json::json!({ "id": id, "path": file.rel, "hash": file.sha256 }),
            Err(e) => serde_json::json!({ "id": audited_path(&id), "reason": e.to_string() }),
        };
        self.append_audit_as(
            0,
            actor_label(&actor),
            "wp.integrity.restore",
            Some(detail.id.as_str()),
            &payload.to_string(),
            outcome_of(&done),
        )
        .await;
        let file = done?;
        self.after_file_action(&detail, |rec| {
            drop_file(&mut rec.result, &file.rel);
            for hit in &file.malware {
                if !rec.result.malware.contains(hit) {
                    rec.result.malware.push(hit.clone());
                }
            }
        })
        .await;
        self.wp_integrity_stored(HostingSelector::Id(detail.id))
            .await
    }

    /// What a hosting holds in quarantine. Metadata only, never content.
    pub async fn scan_quarantine_list(
        &self,
        sel: HostingSelector,
    ) -> Result<QuarantineList, RpcError> {
        let detail = self.get(sel).await?;
        Ok(self
            .adapters
            .site_scan_quarantine_list(
                std::path::Path::new(&self.paths.quarantine_dir),
                detail.id.as_str(),
                QUARANTINE_LIST_CAP,
            )
            .await?)
    }

    /// Vouch for one reported file, as it stands. New content flags it again.
    pub async fn scan_file_trust(
        &self,
        sel: HostingSelector,
        rel: String,
        sha256: String,
        actor: String,
    ) -> Result<WpIntegrityScanResult, RpcError> {
        let detail = self.scan_action_target(sel).await?;
        let done = self
            .trust_items(&detail, |result| {
                check_trustable(item_named(result, &rel, &sha256)?)?;
                Ok(vec![(rel.clone(), sha256.clone())])
            })
            .await;
        let mut payload = serde_json::json!({ "path": audited_path(&rel), "hash": sha256 });
        if let Err(e) = &done {
            payload["reason"] = e.to_string().into();
        }
        self.append_audit_as(
            0,
            actor_label(&actor),
            "wp.integrity.trust",
            Some(detail.id.as_str()),
            &payload.to_string(),
            outcome_of(&done),
        )
        .await;
        done?;
        self.request_rescan(detail.id.as_str()).await;
        self.wp_integrity_stored(HostingSelector::Id(detail.id))
            .await
    }

    /// Vouch for every change to review that can be: for bulk edits. Nothing with
    /// a rule hit, nothing a comparison failed.
    pub async fn scan_trust_all_review(
        &self,
        sel: HostingSelector,
        actor: String,
    ) -> Result<WpIntegrityScanResult, RpcError> {
        let detail = self.scan_action_target(sel).await?;
        let done = self
            .trust_items(&detail, |result| {
                let items: Vec<(String, String)> = result
                    .trust_all_items()
                    .map(|f| (f.rel.clone(), f.sha256.clone()))
                    .collect();
                if items.is_empty() {
                    return Err(refuse("nothing here can be trusted all at once"));
                }
                Ok(items)
            })
            .await;
        match &done {
            // Every file on the record, in rows of a size that stays readable.
            Ok(items) => {
                for chunk in items.chunks(TRUST_AUDIT_CHUNK) {
                    let files: Vec<_> = chunk
                        .iter()
                        .map(|(path, hash)| serde_json::json!({ "path": path, "hash": hash }))
                        .collect();
                    self.append_audit_as(
                        0,
                        actor_label(&actor),
                        "wp.integrity.trust_all",
                        Some(detail.id.as_str()),
                        &serde_json::json!({ "total": items.len(), "files": files }).to_string(),
                        "ok",
                    )
                    .await;
                }
            }
            Err(e) => {
                self.append_audit_as(
                    0,
                    actor_label(&actor),
                    "wp.integrity.trust_all",
                    Some(detail.id.as_str()),
                    &serde_json::json!({ "reason": e.to_string() }).to_string(),
                    "refused",
                )
                .await;
            }
        }
        done?;
        self.request_rescan(detail.id.as_str()).await;
        self.wp_integrity_stored(HostingSelector::Id(detail.id))
            .await
    }

    /// Add what `pick` chooses from the stored result to the trust list and take it
    /// off the card. The list first: a card that lost an item the list didn't gain
    /// would say more than is true. Returns what was added.
    async fn trust_items(
        &self,
        detail: &HostingDetail,
        pick: impl FnOnce(&WpIntegrityScanResult) -> Result<Vec<(String, String)>, RpcError>,
    ) -> Result<Vec<(String, String)>, RpcError> {
        let id = detail.id.as_str();
        let _record = self.site_scan.record.lock().await;
        let mut rec = self.scan_action_record(id).await?;
        let items = pick(&rec.result)?;
        if items.iter().any(|(_, hash)| decode_hash(hash).is_none()) {
            return Err(stale());
        }
        let mut trust = self.read_trust(id).await?;
        trust.extend(items.iter().cloned());
        if trust.len() > TRUST_CAP {
            return Err(RpcError::Conflict {
                message: format!(
                    "this site's trust list is full ({TRUST_CAP} files); fix some of what's on it instead"
                ),
            });
        }
        self.write_trust(id, &trust).await?;
        for (rel, sha256) in &items {
            drop_trusted(&mut rec.result, rel, sha256);
        }
        rec.result.awaiting_rescan = true;
        self.set_stored_integrity_scan(id, &rec).await;
        Ok(items)
    }

    async fn read_trust(&self, hosting_id: &str) -> Result<BTreeMap<String, String>, RpcError> {
        let json = hyperion_state::hosting_kv::get(&self.pool, hosting_id, SCAN_TRUST_KV_KEY)
            .await
            .map_err(|e| RpcError::Internal_with(format!("trust list: {e}")))?;
        Ok(json.as_deref().map(parse_trust).unwrap_or_default())
    }

    async fn write_trust(
        &self,
        hosting_id: &str,
        trust: &BTreeMap<String, String>,
    ) -> Result<(), RpcError> {
        let json = serde_json::to_string(trust)
            .map_err(|e| RpcError::Internal_with(format!("trust list: {e}")))?;
        hyperion_state::hosting_kv::set(
            &self.pool,
            hosting_id,
            SCAN_TRUST_KV_KEY,
            &json,
            now_secs(),
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("trust list: {e}")))
    }

    /// The list as a scan takes it. One that can't be read trusts nothing: at worst
    /// a file comes back to the card.
    pub(super) async fn scan_trust_map(&self, hosting_id: &str) -> BTreeMap<String, [u8; 32]> {
        match self.read_trust(hosting_id).await {
            Ok(trust) => trust
                .into_iter()
                .filter_map(|(path, hash)| Some((path, decode_hash(&hash)?)))
                .collect(),
            Err(e) => {
                tracing::warn!(error = %e, "site scan: trust list unreadable");
                BTreeMap::new()
            }
        }
    }

    /// What a finished scan says about the list. A path whose content the scan now
    /// reports with another hash is no longer what anyone vouched for, and if it
    /// came back later it should be asked about again; one with nothing there frees
    /// its room. The worker's word can only take entries away, so a worker that
    /// lies here gets its files flagged. The caller holds the record lock.
    pub(super) async fn prune_scan_trust(
        &self,
        hosting_id: &str,
        reported: &[(String, String)],
        gone: &[String],
    ) {
        let Ok(mut trust) = self.read_trust(hosting_id).await else {
            return;
        };
        let before = trust.len();
        for rel in gone {
            trust.remove(rel);
        }
        for (rel, sha256) in reported {
            if !sha256.is_empty() && trust.get(rel).is_some_and(|t| t != sha256) {
                trust.remove(rel);
            }
        }
        if trust.len() != before {
            if let Err(e) = self.write_trust(hosting_id, &trust).await {
                tracing::warn!(error = %e, "site scan: trust list not updated");
            }
        }
    }

    /// Replace a plugin or theme with wordpress.org's copy of the version it runs,
    /// if wordpress.org is what the scan compared it with. A private plugin sharing
    /// a slug with a wordpress.org one would be swapped for a different plugin, and
    /// a card isn't what should stand in the way of that.
    pub async fn scan_component_reinstall(
        &self,
        sel: HostingSelector,
        slug: String,
        theme: bool,
    ) -> Result<hyperion_types::WpPluginActionResult, RpcError> {
        let detail = self.get(sel).await?;
        let rec = self.scan_action_record(detail.id.as_str()).await?;
        let failed = if theme {
            &rec.result.themes_failed
        } else {
            &rec.result.plugins_failed
        };
        let Some(component) = failed.iter().find(|c| c.slug == slug) else {
            return Err(stale());
        };
        if !rec.result.reinstallable_from_wordpress_org(&slug) {
            return Err(RpcError::Conflict {
                message: format!(
                    "this was compared with {}, not wordpress.org, so wordpress.org's copy isn't the fix",
                    rec.result.reference_of(&slug)
                ),
            });
        }
        let sel = HostingSelector::Id(detail.id.clone());
        if !theme {
            return self
                .wp_plugin_action(sel, slug, hyperion_types::WpPluginAction::Reinstall)
                .await;
        }
        if component.version.is_empty() {
            return Err(stale());
        }
        let action = hyperion_types::WpThemeAction::Reinstall {
            version: component.version.clone(),
        };
        let out = self.wp_theme_action(sel, slug, action).await?;
        Ok(hyperion_types::WpPluginActionResult {
            state: out.state,
            message: out.message,
            output_tail: out.output_tail,
        })
    }
}
