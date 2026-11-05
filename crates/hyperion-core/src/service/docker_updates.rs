//! Image updates: has the tag a container runs moved on at its registry?
//!
//! Once a day (staggered by the agent) every unique image reference used by a
//! known container is looked up, one at a time, and the answer is kept in
//! `docker_image_checks`. The question is only "is the digest under this tag
//! still the one this node pulled"; a newer version tag is never looked for.
//! Hyperion pulls nothing, creates nothing and starts nothing.
//!
//! How the registry is asked is the adapter's business (a `HEAD` with an
//! anonymous token for Docker Hub so the node's pull budget is untouched,
//! `docker buildx imagetools` with Docker's own credential store for the
//! rest). This file decides what an answer, or the lack of one, means.

use super::docker::db_err;
use super::*;
use hyperion_adapters::docker::{
    parse_image_inspect, DockerCmd, DockerError, ImageRef, LocalImage,
};
use hyperion_adapters::docker_registry::{repo_name_of, RemoteDigestError};
use hyperion_state::docker::ImageCheckRow;
use hyperion_types::docker::{DockerContainer, ImageUpdateState};
use std::collections::{BTreeSet, HashMap};
use std::time::Duration;

/// A reference answered (or tried) less than this long ago is left alone, so
/// an agent that restarts does not ask everything again.
const RECHECK_AFTER_SECS: i64 = 20 * 3600;
/// Most unique references one pass looks at.
const MAX_REFS_PER_TICK: usize = 100;
/// A row for a reference no container uses is kept this long, so a stack that
/// is taken down and brought back is not told about the same digest twice.
const KEEP_UNUSED_SECS: i64 = 30 * 86_400;
/// `docker image inspect` prints one image.
const IMAGE_MAX_BYTES: usize = 4 * 1024 * 1024;
/// Between two registry questions. Zero under test.
const LOOKUP_PAUSE: Duration = Duration::from_millis(if cfg!(test) { 0 } else { 1500 });
/// The longest registry text carried into a reason.
const REASON_MAX_CHARS: usize = 160;
const ALERT_HREF: &str = "/docker";

const REASON_PINNED: &str = "pinned to a digest, so the tag cannot move";
const REASON_BUILT: &str = "built on this node, so there is no registry digest to compare";
const REASON_OTHER_REPO: &str = "pulled from another repository than the one it is named after";
const REASON_NO_TAG: &str = "started from an image id, so there is no tag to check";
const REASON_MISSING: &str = "the image is not on this node any more";
const REASON_NO_ANSWER: &str = "the registry has not answered yet";

const STATE_CURRENT: &str = "current";
const STATE_UPDATE: &str = "update";
const STATE_CANNOT: &str = "cannot:";

/// Why a lookup that failed leaves no answer, in a sentence for the page.
fn error_reason(e: &RemoteDigestError) -> String {
    match e {
        RemoteDigestError::RateLimited => {
            "the registry's rate limit was reached, it is asked again tomorrow".into()
        }
        RemoteDigestError::Unauthorized => {
            "unauthorized: the registry wants a login that Docker on this node does not have".into()
        }
        RemoteDigestError::Unavailable(t) => {
            let t: String = t
                .chars()
                .filter(|c| !c.is_control())
                .take(REASON_MAX_CHARS)
                .collect();
            format!("the registry could not be asked: {t}")
        }
        RemoteDigestError::Unsupported => {
            "buildx missing: this registry can only be asked through docker buildx".into()
        }
    }
}

/// The repository's digests among the local ones: only entries for the
/// repository the reference names, however Docker Hub is spelled.
fn own_digests(local: &LocalImage) -> Vec<&str> {
    let Some(repo) = repo_name_of(&local.image_ref) else {
        return Vec::new();
    };
    local
        .repo_digests
        .iter()
        .filter_map(|d| {
            let (_, digest) = d.split_once('@')?;
            (repo_name_of(d).as_deref() == Some(repo.as_str())).then_some(digest)
        })
        .collect()
}

/// A reason the registry need not be asked at all, from the local copy alone.
fn unverifiable_locally(local: &LocalImage) -> Option<&'static str> {
    if local.pinned {
        Some(REASON_PINNED)
    } else if local.repo_digests.is_empty() {
        Some(REASON_BUILT)
    } else if own_digests(local).is_empty() {
        Some(REASON_OTHER_REPO)
    } else {
        None
    }
}

fn cannot(reason: impl Into<String>) -> ImageUpdateState {
    ImageUpdateState::CannotVerify {
        reason: reason.into(),
    }
}

/// Decide what to say about one container's image.
///
/// * The container runs another image than the tag's local copy: the tag was
///   pulled and the container not recreated. That is a fact about this node
///   and needs no registry.
/// * A pinned reference, an image built here, or one pulled under another
///   name has nothing to compare.
/// * Otherwise the registry's digest is compared with the digests the local
///   copy was pulled with.
/// * A failed lookup never reads as "up to date". If an earlier lookup
///   answered, that answer (its remote digest, told against what is local
///   now) is kept; if not, the reason is shown.
pub fn image_state(
    local: &LocalImage,
    container_image_id: &str,
    remote: Result<&str, &RemoteDigestError>,
    last: Option<&ImageCheckRow>,
) -> ImageUpdateState {
    if !container_image_id.is_empty()
        && !local.image_id.is_empty()
        && container_image_id != local.image_id
    {
        return ImageUpdateState::NotRecreated;
    }
    if let Some(reason) = unverifiable_locally(local) {
        return cannot(reason);
    }
    let mine = own_digests(local);
    let digest: Option<&str> = match remote {
        Ok(d) => Some(d),
        Err(_) => last
            .map(|l| l.remote_digest.as_str())
            .filter(|d| !d.is_empty()),
    };
    if let Some(d) = digest {
        return if mine.contains(&d) {
            ImageUpdateState::UpToDate
        } else {
            ImageUpdateState::UpdateAvailable
        };
    }
    // A kept answer without a digest (a row written by hand, or by an older
    // build): its word stands.
    if let (Err(_), Some(l)) = (remote, last) {
        match l.state.as_str() {
            STATE_UPDATE => return ImageUpdateState::UpdateAvailable,
            STATE_CURRENT => return ImageUpdateState::UpToDate,
            _ => {}
        }
    }
    cannot(match remote {
        Err(e) => error_reason(e),
        Ok(_) => REASON_NO_ANSWER.to_string(),
    })
}

fn state_word(s: &ImageUpdateState) -> String {
    match s {
        ImageUpdateState::UpToDate => STATE_CURRENT.into(),
        ImageUpdateState::UpdateAvailable => STATE_UPDATE.into(),
        ImageUpdateState::NotRecreated => "unknown".into(),
        ImageUpdateState::CannotVerify { reason } => format!("{STATE_CANNOT}{reason}"),
    }
}

/// What to show for one container, from the row its image reference has.
///
/// The row speaks for the container only if the container existed when the
/// row was read; a container started since has not been checked yet.
fn container_update(row: &ImageCheckRow, c: &DockerContainer) -> Option<ImageUpdateState> {
    let not_recreated = row.checked_at > 0
        && c.started_at <= row.checked_at
        && !row.local_digest.is_empty()
        && !c.image_id.is_empty()
        && row.local_digest != c.image_id;
    if not_recreated {
        return Some(ImageUpdateState::NotRecreated);
    }
    if let Some(reason) = row.state.strip_prefix(STATE_CANNOT) {
        return Some(cannot(reason));
    }
    if c.started_at > row.checked_at {
        return None;
    }
    match row.state.as_str() {
        STATE_CURRENT => Some(ImageUpdateState::UpToDate),
        STATE_UPDATE => Some(ImageUpdateState::UpdateAvailable),
        _ => None,
    }
}

/// A reference that names an image by id (`sha256:...`, or 12 to 64 bare hex
/// digits): what a container has when its tag was moved away from it.
fn is_image_id(r: &str) -> bool {
    let h = r.strip_prefix("sha256:").unwrap_or(r);
    (12..=64).contains(&h.len()) && h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// When a rate-limited or otherwise failed reference may be asked again: not
/// before the next UTC day, and never sooner than the daily rhythm allows.
fn retry_after(now: i64, e: &RemoteDigestError) -> i64 {
    let next_day = (now.div_euclid(86_400) + 1) * 86_400;
    match e {
        RemoteDigestError::RateLimited => next_day.max(now + RECHECK_AFTER_SECS),
        _ => now + RECHECK_AFTER_SECS,
    }
}

fn due(row: Option<&ImageCheckRow>, now: i64) -> bool {
    match row {
        None => true,
        Some(r) => {
            r.retry_after <= now && !(r.checked_at > 0 && now - r.checked_at < RECHECK_AFTER_SECS)
        }
    }
}

impl<A: AdapterPort + 'static> HostingService<A> {
    /// Fill `update` of each container from the stored answers. A database
    /// error leaves them unset: a missing badge is not worth failing a read.
    pub(super) async fn docker_attach_updates(&self, containers: &mut [DockerContainer]) {
        let rows = match hyperion_state::docker::list_image_checks(&self.pool).await {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!(error = %e, "docker: image checks not attached");
                return;
            }
        };
        if rows.is_empty() {
            return;
        }
        let by_ref: HashMap<&str, &ImageCheckRow> =
            rows.iter().map(|r| (r.image_ref.as_str(), r)).collect();
        for c in containers {
            let row = by_ref.get(c.image.as_str());
            c.update = row.and_then(|r| container_update(r, c));
            c.update_checked_at = match (&c.update, row) {
                (Some(_), Some(r)) => r.checked_at,
                _ => 0,
            };
        }
    }

    /// The daily image check. A no-op while the module is off, or while the
    /// daemon does not answer.
    pub async fn docker_updates_tick(&self) -> Result<(), RpcError> {
        self.docker_updates_tick_at(now_secs()).await
    }

    pub(super) async fn docker_updates_tick_at(&self, now: i64) -> Result<(), RpcError> {
        if !self.docker_module_enabled().await {
            return Ok(());
        }
        let status = self.docker_overview().await?;
        if !status.daemon_ok {
            return Ok(());
        }
        let used: BTreeSet<String> = status
            .projects
            .iter()
            .flat_map(|p| p.containers.iter())
            .map(|c| c.image.clone())
            .filter(|i| !i.is_empty() && ImageRef::parse(i).is_ok())
            .collect();
        let refs: Vec<String> = used.iter().take(MAX_REFS_PER_TICK).cloned().collect();

        let mut asked = false;
        for r in &refs {
            let last = hyperion_state::docker::get_image_check(&self.pool, r)
                .await
                .map_err(|e| db_err("image check", e))?;
            if !due(last.as_ref(), now) {
                continue;
            }
            if asked {
                tokio::time::sleep(LOOKUP_PAUSE).await;
            }
            match self.docker_check_one(r, last, now, &mut asked).await {
                Step::Next => {}
                // The registry said stop, or docker did: the rest wait for
                // the next pass.
                Step::Stop => break,
            }
        }

        self.docker_updates_notify(&refs).await?;
        let seen: Vec<String> = used.into_iter().collect();
        let _ =
            hyperion_state::docker::prune_image_checks(&self.pool, &seen, now - KEEP_UNUSED_SECS)
                .await;
        // The overview serves a snapshot; put the new answers on it now
        // rather than at the next 30 s tick.
        let mut snap = self.docker_snapshot.write().await;
        if let Some(s) = snap.as_mut() {
            for p in &mut s.projects {
                self.docker_attach_updates(&mut p.containers).await;
            }
        }
        Ok(())
    }

    /// Look at one reference: the local copy, then (if there is anything to
    /// compare) the registry, and write the row.
    async fn docker_check_one(
        &self,
        image: &str,
        last: Option<ImageCheckRow>,
        now: i64,
        asked: &mut bool,
    ) -> Step {
        let Ok(reference) = ImageRef::parse(image) else {
            return Step::Next;
        };
        let mut row = last.clone().unwrap_or_else(|| ImageCheckRow {
            image_ref: image.to_string(),
            ..Default::default()
        });
        let put = |row: ImageCheckRow| async move {
            if let Err(e) = hyperion_state::docker::put_image_check(&self.pool, &row).await {
                tracing::warn!(error = %e, "docker: image check not saved");
            }
        };
        if is_image_id(image) {
            row.state = format!("{STATE_CANNOT}{REASON_NO_TAG}");
            row.checked_at = now;
            row.retry_after = 0;
            put(row).await;
            return Step::Next;
        }

        let local = match self
            .adapters
            .docker_read(DockerCmd::ImageInspect(reference.clone()), IMAGE_MAX_BYTES)
            .await
            .and_then(|raw| parse_image_inspect(&raw, image))
        {
            Ok(Some(l)) => l,
            Ok(None) => {
                row.local_digest.clear();
                row.remote_digest.clear();
                row.state = format!("{STATE_CANNOT}{REASON_MISSING}");
                row.checked_at = now;
                row.retry_after = 0;
                put(row).await;
                return Step::Next;
            }
            Err(DockerError::NotResponding | DockerError::NotInstalled) => return Step::Stop,
            Err(e) => {
                tracing::debug!(error = %e, "docker: image not read");
                return Step::Next;
            }
        };
        row.local_digest = local.image_id.clone();

        if let Some(reason) = unverifiable_locally(&local) {
            row.remote_digest.clear();
            row.state = format!("{STATE_CANNOT}{reason}");
            row.checked_at = now;
            row.retry_after = 0;
            put(row).await;
            return Step::Next;
        }

        *asked = true;
        let remote = self.adapters.docker_remote_digest(reference).await;
        // Whether the registry answered or not, the verdict for the TAG is
        // taken against its own local id; a container that runs something
        // else is told apart when it is shown.
        let state = image_state(&local, &local.image_id, remote.as_deref(), last.as_ref());
        let mut step = Step::Next;
        match &remote {
            Ok(d) => {
                row.remote_digest = d.clone();
                row.state = state_word(&state);
                row.checked_at = now;
                row.retry_after = 0;
            }
            Err(e) => {
                row.retry_after = retry_after(now, e);
                row.state = state_word(&state);
                // A kept answer keeps its age; no answer is stamped with the
                // time of the try.
                if matches!(state, ImageUpdateState::CannotVerify { .. }) {
                    row.checked_at = now;
                }
                if *e == RemoteDigestError::RateLimited {
                    step = Step::Stop;
                }
            }
        }
        put(row).await;
        step
    }

    /// One folded card per node, when some image has an update the operator
    /// was not yet told about. Bell only: update notices never go to Slack or
    /// mail.
    async fn docker_updates_notify(&self, refs: &[String]) -> Result<(), RpcError> {
        let mut with_update = Vec::new();
        for r in refs {
            if let Some(row) = hyperion_state::docker::get_image_check(&self.pool, r)
                .await
                .map_err(|e| db_err("image check", e))?
            {
                if row.state == STATE_UPDATE && !row.remote_digest.is_empty() {
                    with_update.push(row);
                }
            }
        }
        let fresh: Vec<&ImageCheckRow> = with_update
            .iter()
            .filter(|r| r.remote_digest != r.notified_digest)
            .collect();
        if fresh.is_empty() {
            return Ok(());
        }
        let node = self.current_node_id();
        let count = with_update.len().to_string();
        self.notify_admins_say(
            "info",
            "ops.docker_updates",
            &[("node", node.as_str()), ("count", count.as_str())],
            ALERT_HREF,
            &format!("docker.update:{node}"),
        )
        .await;
        for r in fresh {
            let mut r = r.clone();
            r.notified_digest = r.remote_digest.clone();
            hyperion_state::docker::put_image_check(&self.pool, &r)
                .await
                .map_err(|e| db_err("image check", e))?;
        }
        Ok(())
    }
}

enum Step {
    Next,
    Stop,
}
