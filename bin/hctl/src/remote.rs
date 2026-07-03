//! `hctl remote` — drive the `/api/v1` HTTP API from the shell.
//!
//! Unlike the rest of `hctl` (which speaks the local RPC socket), this talks
//! to the Bearer-authenticated HTTP edge, so it works from ANY machine with a
//! key — CI, a laptop, another server. Connection settings resolve in order:
//! `--url/--key` flags → `HYPERION_API_URL`/`HYPERION_API_KEY` env →
//! `~/.config/hyperion/remote.toml` (written by `hctl remote login`).
//!
//! Every command prints the API's JSON response verbatim (pretty-printed), so
//! it pipes cleanly into `jq`. A non-2xx status prints the error envelope and
//! exits non-zero.

use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};
use reqwest::{Client, Method};
use serde_json::{json, Value};
use std::time::Duration;

/// Connection options shared by every `remote` subcommand.
#[derive(Args, Debug)]
pub struct RemoteConn {
    /// API base URL, e.g. https://panel.example.com (overrides env + config).
    #[arg(long, global = true)]
    pub url: Option<String>,
    /// API key `hyp_…` (overrides env + config).
    #[arg(long, global = true)]
    pub key: Option<String>,
    /// Skip TLS certificate verification (self-signed panels).
    #[arg(long, global = true)]
    pub insecure: bool,
}

#[derive(Subcommand, Debug)]
pub enum RemoteCmd {
    /// Save the API url + key to ~/.config/hyperion/remote.toml.
    Login,
    /// Show the presented key's identity (GET /api/v1/me).
    Me,
    /// List hostings (GET /api/v1/hostings).
    List {
        #[arg(long)]
        state: Option<String>,
        #[arg(long)]
        node: Option<String>,
        #[arg(long)]
        q: Option<String>,
        #[arg(long)]
        limit: Option<usize>,
        #[arg(long)]
        cursor: Option<String>,
    },
    /// Show one hosting (GET /api/v1/hostings/{id}).
    Get { id: String },
    /// Create a hosting (POST /api/v1/hostings).
    Create {
        #[arg(long)]
        domain: String,
        /// PHP version wire value, e.g. v8_3.
        #[arg(long)]
        php: Option<String>,
        #[arg(long)]
        node: Option<String>,
    },
    /// Suspend a hosting.
    Suspend { id: String },
    /// Resume a hosting.
    Resume { id: String },
    /// Delete a hosting (async job).
    Delete {
        id: String,
        #[arg(long)]
        keep_user: bool,
        #[arg(long)]
        keep_database: bool,
        /// Poll the job to completion.
        #[arg(long)]
        wait: bool,
    },
    /// Run a backup now (async job).
    Backup {
        id: String,
        #[arg(long)]
        wait: bool,
    },
    /// List a hosting's backups.
    Backups { id: String },
    /// Issue an ACME certificate (async job).
    Cert {
        id: String,
        #[arg(long)]
        staging: bool,
        #[arg(long)]
        wait: bool,
    },
    /// Poll a background job (GET /api/v1/jobs/{id}).
    Job { id: String },
    /// List cluster nodes (GET /api/v1/nodes).
    Nodes,
    /// Print the OpenAPI 3 spec (GET /api/v1/openapi.json).
    Openapi,
}

/// Resolved connection: base URL (no trailing slash) + key + a built client.
struct Conn {
    base: String,
    key: String,
    client: Client,
}

pub async fn run(conn: &RemoteConn, cmd: &RemoteCmd) -> Result<()> {
    // `login` is special: it writes config rather than calling the API.
    if let RemoteCmd::Login = cmd {
        let (url, key) = (
            require(&conn.url, "HYPERION_API_URL", "--url")?,
            require(&conn.key, "HYPERION_API_KEY", "--key")?,
        );
        write_config(&url, &key)?;
        println!("Saved {}", config_path()?.display());
        return Ok(());
    }

    let c = resolve(conn)?;
    match cmd {
        RemoteCmd::Login => unreachable!("handled above"),
        RemoteCmd::Me => get(&c, "/api/v1/me").await,
        RemoteCmd::List {
            state,
            node,
            q,
            limit,
            cursor,
        } => {
            let mut qs: Vec<String> = Vec::new();
            if let Some(v) = state {
                qs.push(format!("state={v}"));
            }
            if let Some(v) = node {
                qs.push(format!("node={v}"));
            }
            if let Some(v) = q {
                qs.push(format!("q={v}"));
            }
            if let Some(v) = limit {
                qs.push(format!("limit={v}"));
            }
            if let Some(v) = cursor {
                qs.push(format!("cursor={v}"));
            }
            let path = if qs.is_empty() {
                "/api/v1/hostings".to_string()
            } else {
                format!("/api/v1/hostings?{}", qs.join("&"))
            };
            get(&c, &path).await
        }
        RemoteCmd::Get { id } => get(&c, &format!("/api/v1/hostings/{id}")).await,
        RemoteCmd::Create { domain, php, node } => {
            let mut body = json!({ "domain": domain });
            if let Some(v) = php {
                body["php_version"] = json!(v);
            }
            if let Some(v) = node {
                body["node"] = json!(v);
            }
            send(&c, Method::POST, "/api/v1/hostings", Some(body)).await
        }
        RemoteCmd::Suspend { id } => {
            send(
                &c,
                Method::POST,
                &format!("/api/v1/hostings/{id}/suspend"),
                None,
            )
            .await
        }
        RemoteCmd::Resume { id } => {
            send(
                &c,
                Method::POST,
                &format!("/api/v1/hostings/{id}/resume"),
                None,
            )
            .await
        }
        RemoteCmd::Delete {
            id,
            keep_user,
            keep_database,
            wait,
        } => {
            let path = format!(
                "/api/v1/hostings/{id}?keep_user={keep_user}&keep_database={keep_database}"
            );
            let v = send_value(&c, Method::DELETE, &path, None).await?;
            maybe_wait(&c, &v, *wait).await
        }
        RemoteCmd::Backup { id, wait } => {
            let v = send_value(
                &c,
                Method::POST,
                &format!("/api/v1/hostings/{id}/backup"),
                None,
            )
            .await?;
            maybe_wait(&c, &v, *wait).await
        }
        RemoteCmd::Backups { id } => get(&c, &format!("/api/v1/hostings/{id}/backups")).await,
        RemoteCmd::Cert { id, staging, wait } => {
            let body = json!({ "staging": staging });
            let v = send_value(
                &c,
                Method::POST,
                &format!("/api/v1/hostings/{id}/cert"),
                Some(body),
            )
            .await?;
            maybe_wait(&c, &v, *wait).await
        }
        RemoteCmd::Job { id } => get(&c, &format!("/api/v1/jobs/{id}")).await,
        RemoteCmd::Nodes => get(&c, "/api/v1/nodes").await,
        RemoteCmd::Openapi => get(&c, "/api/v1/openapi.json").await,
    }
}

/// Build the client + resolve url/key from flags → env → config file.
fn resolve(conn: &RemoteConn) -> Result<Conn> {
    let cfg = read_config().unwrap_or_default();
    let url = conn
        .url
        .clone()
        .or_else(|| std::env::var("HYPERION_API_URL").ok())
        .or(cfg.url)
        .context("no API url — pass --url, set HYPERION_API_URL, or run `hctl remote login`")?;
    let key = conn
        .key
        .clone()
        .or_else(|| std::env::var("HYPERION_API_KEY").ok())
        .or(cfg.key)
        .context("no API key — pass --key, set HYPERION_API_KEY, or run `hctl remote login`")?;
    let client = Client::builder()
        .danger_accept_invalid_certs(conn.insecure)
        .build()
        .context("build HTTP client")?;
    Ok(Conn {
        base: url.trim_end_matches('/').to_string(),
        key,
        client,
    })
}

/// GET `path` and print the JSON (exit non-zero on a non-2xx status).
async fn get(c: &Conn, path: &str) -> Result<()> {
    print_and_status(send_value(c, Method::GET, path, None).await?)
}

/// Send `method path` with an optional JSON body and print the response.
async fn send(c: &Conn, method: Method, path: &str, body: Option<Value>) -> Result<()> {
    print_and_status(send_value(c, method, path, body).await?)
}

/// Core request: returns the parsed response, exiting non-zero on a non-2xx.
async fn send_value(c: &Conn, method: Method, path: &str, body: Option<Value>) -> Result<Value> {
    let mut req = c
        .client
        .request(method.clone(), format!("{}{}", c.base, path))
        .bearer_auth(&c.key);
    if let Some(b) = body {
        req = req.json(&b);
    }
    let resp = req
        .send()
        .await
        .with_context(|| format!("{method} {path}"))?;
    let status = resp.status();
    let v: Value = resp.json().await.unwrap_or(Value::Null);
    if !status.is_success() {
        // Print the error envelope, then fail with the status.
        eprintln!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
        bail!("HTTP {}", status.as_u16());
    }
    Ok(v)
}

/// Pretty-print a successful value + exit 0.
fn print_and_status(v: Value) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(&v)?);
    Ok(())
}

/// If `--wait` and the value carries a `job_id`, poll it to completion;
/// otherwise just print the value.
async fn maybe_wait(c: &Conn, v: &Value, wait: bool) -> Result<()> {
    let job_id = v.get("job_id").and_then(|j| j.as_str());
    match (wait, job_id) {
        (true, Some(id)) => {
            eprintln!("job {id} accepted — polling…");
            loop {
                let job = send_value(c, Method::GET, &format!("/api/v1/jobs/{id}"), None).await?;
                let state = job.get("state").and_then(|s| s.as_str()).unwrap_or("");
                let progress = job.get("progress").and_then(|p| p.as_i64()).unwrap_or(0);
                eprintln!("  {state} {progress}%");
                if state != "running" {
                    return print_and_status(job);
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
        _ => print_and_status(v.clone()),
    }
}

// ── config file ──────────────────────────────────────────────────────────

#[derive(Default, serde::Serialize, serde::Deserialize)]
struct RemoteConfig {
    url: Option<String>,
    key: Option<String>,
}

fn config_path() -> Result<std::path::PathBuf> {
    let home = std::env::var("HOME").context("HOME not set")?;
    Ok(std::path::PathBuf::from(home).join(".config/hyperion/remote.toml"))
}

fn read_config() -> Result<RemoteConfig> {
    let path = config_path()?;
    let text = std::fs::read_to_string(path)?;
    Ok(toml::from_str(&text)?)
}

fn write_config(url: &str, key: &str) -> Result<()> {
    let path = config_path()?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let cfg = RemoteConfig {
        url: Some(url.to_string()),
        key: Some(key.to_string()),
    };
    std::fs::write(&path, toml::to_string(&cfg)?)?;
    // The key is a credential — keep the file private.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn require(flag: &Option<String>, env: &str, flagname: &str) -> Result<String> {
    flag.clone()
        .or_else(|| std::env::var(env).ok())
        .with_context(|| format!("`hctl remote login` needs {flagname} (or ${env})"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_config_toml_round_trips() {
        let cfg = RemoteConfig {
            url: Some("https://panel.example.com".into()),
            key: Some("hyp_abc123".into()),
        };
        let s = toml::to_string(&cfg).expect("serialize");
        let back: RemoteConfig = toml::from_str(&s).expect("deserialize");
        assert_eq!(back.url.as_deref(), Some("https://panel.example.com"));
        assert_eq!(back.key.as_deref(), Some("hyp_abc123"));
    }
}
