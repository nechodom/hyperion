//! The node's verdict on running a PHP-FPM master per site user.

use super::*;

impl<A: AdapterPort + 'static> HostingService<A> {
    /// Whether this node could give every PHP site user its own master, and
    /// what that would cost. Reads the host's facts through the adapter and
    /// the user count from the database; the verdict is `fpm_own::judge`'s.
    ///
    /// `own_users` stays 0 until masters of their own exist to count.
    pub async fn fpm_own_preflight(&self) -> Result<hyperion_types::fpm_own::Preflight, RpcError> {
        let mut facts = self.adapters.fpm_preflight_facts().await;
        facts.php_users = hyperion_state::hostings::count_active_php_users(&self.pool)
            .await
            .map_err(|e| RpcError::Internal_with(format!("count php users: {e}")))?;
        facts.own_users = 0;
        Ok(hyperion_types::fpm_own::judge(&facts))
    }
}
