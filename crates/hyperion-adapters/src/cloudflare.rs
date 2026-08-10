//! Cloudflare DNS provider for automated DNS-01 wildcard issuance.
//!
//! Scaffold: the manual DNS-01 flow works without this. When a
//! Cloudflare API token is present (in `/etc/hyperion/cloudflare.token`
//! or `$HYPERION_CLOUDFLARE_TOKEN`), the service can publish the
//! `_acme-challenge` TXT records itself and finish issuance without the
//! operator touching DNS.
//!
//! Calls go through `curl` (every node already has it; pulling in a HTTP
//! client just for this would double-link a TLS stack) against the
//! Cloudflare v4 API. The token needs `Zone:Read` + `DNS:Edit`.

use crate::AdapterError;

const TOKEN_FILE: &str = "/etc/hyperion/cloudflare.token";
const API: &str = "https://api.cloudflare.com/client/v4";

/// The configured token, if any. File takes precedence over env.
pub fn token() -> Option<String> {
    if let Ok(s) = std::fs::read_to_string(TOKEN_FILE) {
        let t = s.trim().to_string();
        if !t.is_empty() {
            return Some(t);
        }
    }
    std::env::var("HYPERION_CLOUDFLARE_TOKEN")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// True when a token is configured (drives the UI's "Cloudflare
/// (automatic)" option being offered vs. disabled).
pub fn is_configured() -> bool {
    token().is_some()
}

/// Validate a token by listing zones — confirms it's accepted and has at least
/// `Zone:Read`. Returns the number of zones it can see (a quick sanity signal
/// for the operator). Errors if Cloudflare rejects the token.
pub async fn verify_token(token: &str) -> Result<usize, AdapterError> {
    let t = token.trim();
    if t.is_empty() {
        return Err(AdapterError::Other("empty Cloudflare token".into()));
    }
    // Ask the endpoint that exists for exactly this question FIRST.
    // `/zones` conflates two different failures behind one 403: a token
    // that is not a valid token at all, and a valid token that may not
    // list zones. Those need opposite fixes, and the operator was shown
    // neither — just "403". `/user/tokens/verify` answers for ANY API
    // token regardless of its scope, so a failure here is unambiguous.
    //
    // The most common cause of a 403 from a "token with every permission"
    // is that it is not an API Token at all but a Global API Key, which
    // is not a bearer credential and can never work here. Second most
    // common: the token carries an IP-address filter that does not
    // include this node. Both are named below, because Cloudflare's own
    // message for them is terse.
    let verify_url = format!("{API}/user/tokens/verify");
    match curl_json(t, &[&verify_url]).await {
        Ok(v) if v["success"].as_bool() == Some(true) => {}
        Ok(v) => {
            return Err(AdapterError::Other(format!(
                "cloudflare: this token is not accepted ({}). \
                 Two things produce this from a token that looks fully privileged: \
                 (1) it is a Global API Key rather than an API Token — those are \
                 not bearer credentials and cannot be used here; create one under \
                 My Profile -> API Tokens -> Create Token; \
                 (2) the token has an IP-address filter that excludes this server.",
                cf_error_summary(&v)
            )));
        }
        Err(e) => return Err(e),
    }

    // Token is genuine. Now check it can actually see zones, which is a
    // separate permission and a separate remedy.
    let url = format!("{API}/zones?per_page=50");
    let v = curl_json(t, &[&url]).await?;
    if v["success"].as_bool() != Some(true) {
        return Err(AdapterError::Other(format!(
            "cloudflare: the token is valid but cannot list zones ({}). \
             Add the Zone:Read permission, and make sure Zone Resources \
             includes the zone you want to use.",
            cf_error_summary(&v)
        )));
    }
    let zones = v["result"].as_array().map(|a| a.len()).unwrap_or(0);
    if zones == 0 {
        return Err(AdapterError::Other(
            "cloudflare: the token is valid but sees no zones. Its Zone Resources \
             probably name a different account, or none. Re-issue it with \
             Zone:Read + DNS:Edit on the zone you want to use."
                .into(),
        ));
    }
    Ok(zones)
}

/// Flatten Cloudflare's `errors` array into one readable sentence.
///
/// Their shape is `[{"code":1000,"message":"Invalid API Token"}]`, and
/// rendering the raw JSON put punctuation and field names in front of the
/// operator instead of the sentence that tells them what to do.
fn cf_error_summary(v: &serde_json::Value) -> String {
    let msgs: Vec<String> = v["errors"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|e| {
                    let m = e["message"].as_str()?;
                    Some(match e["code"].as_i64() {
                        Some(c) => format!("{m} [code {c}]"),
                        None => m.to_string(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    if msgs.is_empty() {
        "no reason given".to_string()
    } else {
        msgs.join("; ")
    }
}

/// Persist the API token to [`TOKEN_FILE`] with `0600` perms (so DNS-01 issuance
/// can read it without the operator SSHing to the box). Caller should
/// [`verify_token`] first.
pub fn write_token(token: &str) -> Result<(), AdapterError> {
    let t = token.trim();
    if t.is_empty() {
        return Err(AdapterError::Other("empty Cloudflare token".into()));
    }
    if let Some(dir) = std::path::Path::new(TOKEN_FILE).parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    std::fs::write(TOKEN_FILE, format!("{t}\n"))
        .map_err(|e| AdapterError::Other(format!("write {TOKEN_FILE}: {e}")))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(TOKEN_FILE, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| AdapterError::Other(format!("chmod {TOKEN_FILE}: {e}")))?;
    }
    Ok(())
}

async fn curl_json(token: &str, args: &[&str]) -> Result<serde_json::Value, AdapterError> {
    // SECURITY (sec-findings #11): NEVER put the bearer token on argv — it would
    // leak to /proc/<pid>/cmdline (readable by any local user, e.g. a site's
    // PHP-FPM uid) and to debug logs/error strings. Feed the Authorization
    // header to curl via a config file on stdin (`curl --config -`); curl reads
    // it from there and the token never appears in the process command line.
    // `--config -` is consumed before the URL/method args we append on argv.
    // `--fail-with-body`, NOT `-f`. Plain `-f` discards the response body on
    // an HTTP error, so a rejected token surfaced to the operator as bare
    // `exit 22: curl: (22) ... error: 403` while Cloudflare's own JSON —
    // which names the actual reason, e.g. "Invalid API Token" vs
    // "Unauthorized to access requested resource" — was thrown away. Those
    // two need completely different fixes, and the operator was told
    // neither. (curl >= 7.76; Debian 12 ships 7.88.)
    let mut full: Vec<&str> = vec![
        "--fail-with-body",
        "-sS",
        "--max-time",
        "30",
        "--config",
        "-",
        "-H",
        "Content-Type: application/json",
    ];
    full.extend_from_slice(args);
    // curl config syntax: one directive per line; the header value is quoted so
    // it survives intact. The token is confined to this stdin payload.
    let config = format!("header = \"Authorization: Bearer {token}\"\n");
    let out = match crate::cmd::run_with_stdin("/usr/bin/curl", &full, config.as_bytes()).await {
        Ok(body) => body,
        Err(e) => {
            // With `--fail-with-body` the body is on stdout even for a 4xx,
            // but `run_with_stdin` only hands back stderr on failure. Retry
            // once WITHOUT the fail flag so the API's explanation can be
            // parsed and shown, rather than reporting a bare exit code.
            let plain: Vec<&str> = full
                .iter()
                .copied()
                .filter(|a| *a != "--fail-with-body")
                .collect();
            match crate::cmd::run_with_stdin("/usr/bin/curl", &plain, config.as_bytes()).await {
                Ok(body) if !body.trim().is_empty() => body,
                _ => return Err(e),
            }
        }
    };
    serde_json::from_str(&out).map_err(|e| AdapterError::Other(format!("cloudflare json: {e}")))
}

/// Find the zone id whose name is the longest DNS suffix of `record_name`.
async fn zone_id_for(token: &str, record_name: &str) -> Result<(String, String), AdapterError> {
    let url = format!("{API}/zones?per_page=50");
    let v = curl_json(token, &[&url]).await?;
    let zones = v["result"]
        .as_array()
        .ok_or_else(|| AdapterError::Other("cloudflare: no zones in response".into()))?;
    let mut best: Option<(String, String)> = None;
    for z in zones {
        let (Some(id), Some(name)) = (z["id"].as_str(), z["name"].as_str()) else {
            continue;
        };
        if (record_name == name || record_name.ends_with(&format!(".{name}")))
            && best
                .as_ref()
                .map(|(_, n)| name.len() > n.len())
                .unwrap_or(true)
        {
            best = Some((id.to_string(), name.to_string()));
        }
    }
    best.ok_or_else(|| {
        AdapterError::Other(format!(
            "cloudflare: no zone covers {record_name} (is the domain on this account?)"
        ))
    })
}

/// Publish one TXT record per value at `record_name`. Returns the created
/// record ids so the caller can clean them up after issuance.
pub async fn publish_txt(
    token: &str,
    record_name: &str,
    values: &[String],
) -> Result<Vec<String>, AdapterError> {
    let (zone_id, zone_name) = zone_id_for(token, record_name).await?;
    let url = format!("{API}/zones/{zone_id}/dns_records");
    let mut ids = Vec::new();
    for value in values {
        let body = serde_json::json!({
            "type": "TXT",
            "name": record_name,
            "content": value,
            "ttl": 120,
        })
        .to_string();
        let v = curl_json(token, &["-X", "POST", &url, "--data", &body]).await?;
        if v["success"].as_bool() != Some(true) {
            let summary = cf_error_summary(&v);
            // Code 10000 "Authentication error" on a WRITE, after the zone
            // lookup above SUCCEEDED with the same token, is Cloudflare's
            // way of saying the token may read but not edit here. The raw
            // message sends the operator off to re-check credentials that
            // demonstrably work — the actual fix is in the token's scope.
            let hint = if summary.contains("code 10000") {
                format!(
                    " The token READS zones fine (the zone lookup above used it), so this                      is a scope problem, not a credential problem: the token must carry                      Zone -> DNS -> Edit with Zone Resources that include `{zone_name}` —                      and `{zone_name}` must live in the SAME Cloudflare account the token                      was created in. A token cannot cross accounts, no matter its                      permissions."
                )
            } else {
                String::new()
            };
            return Err(AdapterError::Other(format!(
                "cloudflare: TXT create in zone `{zone_name}` failed: {summary}.{hint}"
            )));
        }
        if let Some(id) = v["result"]["id"].as_str() {
            ids.push((zone_id.clone(), id.to_string()));
        }
    }
    // Encode as "zone:id" so cleanup doesn't need to re-resolve the zone.
    Ok(ids.into_iter().map(|(z, i)| format!("{z}:{i}")).collect())
}

/// Delete the TXT records created by `publish_txt`. Best-effort.
pub async fn cleanup_txt(token: &str, record_ids: &[String]) {
    for entry in record_ids {
        let Some((zone, id)) = entry.split_once(':') else {
            continue;
        };
        let url = format!("{API}/zones/{zone}/dns_records/{id}");
        let _ = curl_json(token, &["-X", "DELETE", &url]).await;
    }
}

#[cfg(test)]
mod tests {
    use super::cf_error_summary;

    /// The operator reads this string and nothing else, so it has to be a
    /// sentence rather than rendered JSON. The previous version printed
    /// the raw `errors` value, which put braces and field names in front
    /// of the one thing that mattered.
    #[test]
    fn cloudflare_errors_render_as_a_sentence() {
        // The real shape for a Global API Key pasted as a token.
        let v: serde_json::Value = serde_json::from_str(
            r#"{"success":false,"errors":[{"code":1000,"message":"Invalid API Token"}]}"#,
        )
        .expect("json");
        assert_eq!(cf_error_summary(&v), "Invalid API Token [code 1000]");

        // Several at once, joined rather than truncated to the first.
        let v: serde_json::Value = serde_json::from_str(
            r#"{"errors":[{"code":9109,"message":"Unauthorized to access requested resource"},
                          {"message":"no code here"}]}"#,
        )
        .expect("json");
        assert_eq!(
            cf_error_summary(&v),
            "Unauthorized to access requested resource [code 9109]; no code here"
        );

        // An empty or absent array must still read as prose, never "[]".
        for raw in [
            r#"{"errors":[]}"#,
            r#"{"success":false}"#,
            r#"{"errors":"broken"}"#,
        ] {
            let v: serde_json::Value = serde_json::from_str(raw).expect("json");
            assert_eq!(cf_error_summary(&v), "no reason given", "{raw}");
        }
    }
}
