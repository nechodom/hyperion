//! The background-job tracker behind `/jobs` and the live progress cards.

use super::*;

impl<A: AdapterPort + 'static> HostingService<A> {
    // ================================================================
    //  Generic background-job tracker (`jobs` table). Powers the
    //  "live progress" UX on migration / install / backup / clone /
    //  cert renewal / etc. The orchestrating side (panel, hctl, or a
    //  service method) opens a row with `job_start_*`, ticks
    //  `job_progress_*` at each phase, and closes with
    //  `job_finish_*`. The HTMX-polled web fragment reads `job_get`
    //  every 2 seconds.
    // ================================================================

    /// Open a job row from an in-process caller (the agent itself).
    /// Returns the freshly minted ULID `job_id`.
    pub async fn job_start(
        &self,
        kind: &str,
        target: Option<&str>,
        payload_json: &str,
        actor_label: &str,
        actor_uid: i64,
    ) -> Result<String, RpcError> {
        let id = ulid::Ulid::new().to_string();
        hyperion_state::jobs::start(
            &self.pool,
            hyperion_state::jobs::StartReq {
                id: &id,
                kind,
                target,
                payload_json,
                actor_uid,
                actor_label,
                started_at: now_secs(),
            },
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("job_start: {e}")))?;
        Ok(id)
    }

    /// Service-side progress tick (used by intra-service callers).
    pub async fn job_progress(
        &self,
        id: &str,
        step_label: &str,
        progress_pct: i64,
        log_append: &str,
    ) -> Result<(), RpcError> {
        hyperion_state::jobs::progress(
            &self.pool,
            id,
            step_label,
            progress_pct,
            log_append,
            now_secs(),
        )
        .await
        .map_err(|e| RpcError::Internal_with(format!("job_progress: {e}")))?;
        Ok(())
    }

    /// Replace a job's ordered sub-step list (the named subjobs the progress
    /// page renders).
    pub async fn job_substeps(&self, id: &str, substeps_json: &str) -> Result<(), RpcError> {
        hyperion_state::jobs::set_substeps(&self.pool, id, substeps_json, now_secs())
            .await
            .map_err(|e| RpcError::Internal_with(format!("job_substeps: {e}")))?;
        Ok(())
    }

    /// Advance one sub-step by key (set state/pct/note) and republish the whole
    /// list under `pj`. A method rather than a nested fn so it can see `Self`
    /// and reach `publish_backup_progress`.
    pub(super) async fn bump_substep(
        &self,
        pj: Option<&str>,
        subs: &mut [hyperion_types::JobSubstep],
        key: &str,
        state: &str,
        pct: i64,
        note: &str,
    ) {
        if let Some(s) = subs.iter_mut().find(|s| s.key == key) {
            s.state = state.to_string();
            s.pct = pct;
            if !note.is_empty() {
                s.note = note.to_string();
            }
        }
        self.publish_backup_progress(pj, subs).await;
    }

    /// Read the live sub-steps a running operation is publishing under this job
    /// id (in-memory, keyed by the master job id the caller passed in). Empty
    /// when nothing has been reported (or it was already cleared).
    pub async fn backup_progress(&self, job_id: &str) -> Vec<hyperion_types::JobSubstep> {
        self.backup_progress
            .lock()
            .await
            .get(job_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Publish/replace the sub-steps for a running operation under `job_id`.
    /// Node-local + in-memory; the master mirrors it into the job row by
    /// polling `backup_progress`, and finalizes the row from its OWN last-seen
    /// value on completion — so this map never has to survive past the run.
    /// A no-op when `job_id` is None (internal/transient backups).
    ///
    /// Bounds memory by pruning FULLY-terminal entries once the map grows: a
    /// still-running op always has a non-terminal step, so it is never pruned
    /// out from under itself; a finished op's entry is dropped on a later
    /// insert. The master no longer needs it by then.
    pub(crate) async fn publish_backup_progress(
        &self,
        job_id: Option<&str>,
        substeps: &[hyperion_types::JobSubstep],
    ) {
        let Some(id) = job_id else { return };
        let mut map = self.backup_progress.lock().await;
        if map.len() > 128 {
            map.retain(|_, subs| {
                subs.iter()
                    .any(|s| !matches!(s.state.as_str(), "done" | "failed" | "skipped"))
            });
        }
        map.insert(id.to_string(), substeps.to_vec());
    }

    /// Service-side terminal-state flip.
    pub async fn job_finish(
        &self,
        id: &str,
        ok: bool,
        error: Option<&str>,
    ) -> Result<(), RpcError> {
        hyperion_state::jobs::finish(&self.pool, id, ok, error, now_secs())
            .await
            .map_err(|e| RpcError::Internal_with(format!("job_finish: {e}")))?;
        Ok(())
    }

    /// Look up one job. `None` = unknown id (rotated out or never
    /// existed).
    pub async fn job_get(&self, id: &str) -> Result<Option<hyperion_types::JobView>, RpcError> {
        let row = hyperion_state::jobs::read(&self.pool, id)
            .await
            .map_err(|e| RpcError::Internal_with(format!("job_read: {e}")))?;
        Ok(row.map(job_row_to_view))
    }

    /// Newest-first list. `kind` / `state` are optional pinning
    /// filters; both `None` = all jobs.
    pub async fn job_list(
        &self,
        kind: Option<&str>,
        state: Option<&str>,
        limit: i64,
    ) -> Result<Vec<hyperion_types::JobView>, RpcError> {
        let rows = hyperion_state::jobs::list(&self.pool, kind, state, limit)
            .await
            .map_err(|e| RpcError::Internal_with(format!("job_list: {e}")))?;
        Ok(rows.into_iter().map(job_row_to_view).collect())
    }

    // External (RPC) variants — same as the in-process methods but
    // exposed at the AgentApi boundary. They live here (not as
    // standalone functions) so the panel can call them via the
    // signed RPC envelope same as any other agent method.

    pub async fn job_start_external(
        &self,
        kind: &str,
        target: Option<&str>,
        payload_json: &str,
        actor_label: &str,
        actor_uid: i64,
    ) -> Result<String, RpcError> {
        self.job_start(kind, target, payload_json, actor_label, actor_uid)
            .await
    }

    pub async fn job_progress_external(
        &self,
        id: &str,
        step_label: &str,
        progress_pct: i64,
        log_append: &str,
    ) -> Result<(), RpcError> {
        self.job_progress(id, step_label, progress_pct, log_append)
            .await
    }

    pub async fn job_finish_external(
        &self,
        id: &str,
        ok: bool,
        error: Option<&str>,
    ) -> Result<(), RpcError> {
        self.job_finish(id, ok, error).await
    }

    /// Sweep `running` rows whose `updated_at` is older than
    /// `stale_secs` and flip to `failed`. Run at agent startup and
    /// hourly from the scheduler tick. Without this an agent crash
    /// mid-job leaves the UI polling a forever-spinning row.
    pub async fn jobs_reap_stale(&self, stale_secs: i64) -> Result<u64, RpcError> {
        let n = hyperion_state::jobs::reap_stale(&self.pool, now_secs(), stale_secs)
            .await
            .map_err(|e| RpcError::Internal_with(format!("jobs_reap_stale: {e}")))?;
        if n > 0 {
            tracing::warn!(rows = n, "reaped stale jobs (agent crash mid-run?)");
        }
        Ok(n)
    }

    /// Mark backup runs stuck in `running` past `stale_secs` as failed. A run
    /// that crashed mid-backup (OOM, restart) otherwise sits `running` forever —
    /// blocking retry and showing a permanent spinner. Nothing will finish it.
    pub async fn backups_reap_stale(&self, stale_secs: i64) -> Result<u64, RpcError> {
        let n = hyperion_state::backups::reap_stale(&self.pool, now_secs(), stale_secs)
            .await
            .map_err(|e| RpcError::Internal_with(format!("backups_reap_stale: {e}")))?;
        if n > 0 {
            tracing::warn!(
                rows = n,
                "reaped stale backup runs (agent crash mid-backup?)"
            );
        }
        Ok(n)
    }
}

/// Convert the SQLite row representation into the wire-format `JobView`
/// the UI + hctl consume. Pure mapping, no I/O.
pub(super) fn job_row_to_view(r: hyperion_state::jobs::JobRow) -> hyperion_types::JobView {
    hyperion_types::JobView {
        id: r.id,
        kind: r.kind,
        target: r.target,
        state: r.state,
        step_label: r.step_label,
        progress_pct: r.progress_pct,
        // Best-effort: a malformed blob shows as "no sub-steps" rather than
        // failing the whole job read.
        substeps: serde_json::from_str(&r.substeps_json).unwrap_or_default(),
        log_tail: r.log_tail,
        error: r.error,
        payload_json: r.payload_json,
        actor_uid: r.actor_uid,
        actor_label: r.actor_label,
        started_at: r.started_at,
        updated_at: r.updated_at,
        finished_at: r.finished_at,
    }
}
