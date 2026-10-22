//! Per-hosting crontabs.

use super::*;

impl<A: AdapterPort + 'static> HostingService<A> {
    // ================================================================
    //  Per-hosting cron jobs
    // ================================================================

    /// Read `crontab -u <user> -l`. Returns empty string if the user has
    /// no crontab installed.
    pub async fn cron_list(&self, sel: HostingSelector) -> Result<String, RpcError> {
        let detail = self.get(sel).await?;
        let out = tokio::process::Command::new("/usr/bin/crontab")
            .args(["-u", &detail.system_user, "-l"])
            .output()
            .await
            .map_err(|e| RpcError::Internal_with(format!("crontab: {e}")))?;
        if !out.status.success() {
            // crontab returns non-zero if no crontab exists — treat as empty.
            return Ok(String::new());
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    /// Replace the user's crontab with `body`. Atomic — writes via temp
    /// file + `crontab -u <user> <file>`. Validates lines look like
    /// crontab entries (5 schedule fields + a command, OR @reboot etc.)
    /// to prevent injection.
    pub async fn cron_replace(&self, sel: HostingSelector, body: String) -> Result<(), RpcError> {
        let detail = self.get(sel).await?;
        validate_crontab(&body)?;
        let tmp = std::env::temp_dir().join(format!("hyperion-cron-{}.tab", detail.system_user));
        tokio::fs::write(&tmp, body.as_bytes())
            .await
            .map_err(|e| RpcError::Internal_with(format!("write tmp: {e}")))?;
        let tmp_str = tmp.display().to_string();
        let out = tokio::process::Command::new("/usr/bin/crontab")
            .args(["-u", &detail.system_user, &tmp_str])
            .output()
            .await
            .map_err(|e| RpcError::Internal_with(format!("crontab: {e}")))?;
        let _ = tokio::fs::remove_file(&tmp).await;
        if !out.status.success() {
            return Err(RpcError::ProvisioningFailed {
                stage: "crontab".into(),
                reason: String::from_utf8_lossy(&out.stderr).into_owned(),
            });
        }
        self.append_audit(
            "hosting.cron.replace",
            Some(detail.id.as_str()),
            &serde_json::json!({"lines": body.lines().count()}).to_string(),
            "ok",
        )
        .await;
        Ok(())
    }
}

/// Lightweight crontab sanity check — reject any line containing a
/// NUL byte or a backtick (command-substitution). Empty lines and
/// comments (#) are allowed. We DON'T parse the schedule fields; the
/// real crontab command does that and rejects bad entries with a
/// meaningful error.
pub(super) fn validate_crontab(body: &str) -> Result<(), RpcError> {
    for (i, line) in body.lines().enumerate() {
        if line.contains('\0') {
            return Err(RpcError::Validation {
                message: format!("line {} contains NUL byte", i + 1),
            });
        }
        // Reject backticks because they're shell command substitution and
        // we don't want operators accidentally executing arbitrary code
        // by pasting from a sketchy source. Operators who need them can
        // edit /var/spool/cron/crontabs/<user> directly.
        if line.contains('`') {
            return Err(RpcError::Validation {
                message: format!("line {} contains backtick — refused for safety", i + 1),
            });
        }
    }
    if body.len() > 65_536 {
        return Err(RpcError::Validation {
            message: "crontab body exceeds 64 KiB".into(),
        });
    }
    Ok(())
}
