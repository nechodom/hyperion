//! WP-Cron run by the node (see `hyperion_types::wpcron`).

use super::*;

impl<A: AdapterPort + 'static> HostingService<A> {
    /// Run due WP-Cron events for every live WordPress site that carries the
    /// Hyperion plugin, and keep the module that stops WordPress spawning its
    /// own in step with how that went.
    ///
    /// A site without the plugin's loader is one the operator set to "report
    /// only": Hyperion adds nothing to it, so it keeps WordPress's own cron.
    /// So does a site kept out of search engines, which is what a staging copy
    /// or a test site is: run on a timer, a copy of a shop would send its
    /// reminders and renew its subscriptions all over again, where WordPress
    /// only fires cron when somebody opens it.
    ///
    /// `last_run` carries when each site last ran, between ticks. In memory:
    /// after a restart every site is simply due.
    ///
    /// Returns how many sites ran.
    pub async fn wp_system_cron_tick(
        &self,
        last_run: &mut std::collections::HashMap<String, i64>,
    ) -> Result<i64, RpcError> {
        use hyperion_adapters::wpplugin;
        use hyperion_types::wpcron;
        let rows = wordpress::list_install_roots(&self.pool)
            .await
            .map_err(|e| RpcError::Internal_with(format!("wp installs: {e}")))?;
        let now = now_secs();
        let limit = Arc::new(tokio::sync::Semaphore::new(wpcron::CONCURRENCY));
        let mut runs = tokio::task::JoinSet::new();
        let mut due = std::collections::HashMap::new();
        for (id, root, _) in rows {
            let key = id.as_str().to_string();
            let Ok(detail) = self.get(HostingSelector::Id(id)).await else {
                continue;
            };
            if detail.state != HostingState::Active || detail.system_user.trim().is_empty() {
                continue;
            }
            let on = wpcron::enabled(
                hyperion_state::hosting_kv::get(&self.pool, &key, wpcron::KV_ENABLED)
                    .await
                    .ok()
                    .flatten()
                    .as_deref(),
            );
            if !on || detail.vhost_options.noindex {
                wpplugin::remove_module(&root, wpplugin::Module::Cron).await;
                continue;
            }
            if !wpplugin::loader_path(&root).exists() {
                continue;
            }
            let st = self.wp_cron_state(&key).await;
            if !st.due(now, last_run.get(&key).copied().unwrap_or(0)) {
                continue;
            }
            last_run.insert(key.clone(), now);
            let (adapters, limit, user, htdocs, task_key) = (
                self.adapters.clone(),
                limit.clone(),
                detail.system_user.clone(),
                root.clone(),
                key.clone(),
            );
            runs.spawn(async move {
                let _slot = limit.acquire_owned().await;
                (task_key, adapters.wp_cron_run(&user, &htdocs).await)
            });
            due.insert(key, (detail, root, st));
        }
        let mut ran = 0i64;
        while let Some(joined) = runs.join_next().await {
            let (key, result) = match joined {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e, "wp cron: run panicked");
                    continue;
                }
            };
            let Some((detail, root, mut st)) = due.remove(&key) else {
                continue;
            };
            let at = now_secs();
            match result {
                Ok(()) => {
                    ran += 1;
                    st.record_ok(at);
                    // Only now that the command line has worked here.
                    let state = wpplugin::module_state(
                        &root,
                        wpplugin::Module::Cron,
                        wpplugin::CRON_MODULE,
                    )
                    .await;
                    if matches!(
                        state,
                        wpplugin::FileState::Missing | wpplugin::FileState::Stale
                    ) {
                        if let Err(e) = wpplugin::install_module(
                            &root,
                            &detail.system_user,
                            wpplugin::Module::Cron,
                            wpplugin::CRON_MODULE,
                        )
                        .await
                        {
                            tracing::warn!(domain = %detail.domain, error = %e, "wp cron: module not written");
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(domain = %detail.domain, error = %e, "wp cron: run failed");
                    if st.record_failure(at) {
                        wpplugin::remove_module(&root, wpplugin::Module::Cron).await;
                        self.append_audit(
                            "hosting.wp.system_cron_fallback",
                            Some(&key),
                            &serde_json::json!({"domain": detail.domain, "error": e.to_string()})
                                .to_string(),
                            "ok",
                        )
                        .await;
                    }
                }
            }
            let _ = hyperion_state::hosting_kv::set(
                &self.pool,
                &key,
                wpcron::KV_STATE,
                &st.to_json(),
                at,
            )
            .await;
        }
        Ok(ran)
    }

    async fn wp_cron_state(&self, id: &str) -> hyperion_types::wpcron::State {
        use hyperion_types::wpcron;
        hyperion_state::hosting_kv::get(&self.pool, id, wpcron::KV_STATE)
            .await
            .ok()
            .flatten()
            .and_then(|v| wpcron::State::parse(&v))
            .unwrap_or_default()
    }
}
