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
        /// active | suspended | provisioning | failed
        #[arg(long)]
        state: Option<String>,
        /// Owning node id.
        #[arg(long)]
        node: Option<String>,
        /// Domain substring.
        #[arg(long)]
        q: Option<String>,
        /// Page size (1..200).
        #[arg(long)]
        limit: Option<usize>,
        /// `next_cursor` from the previous page.
        #[arg(long)]
        cursor: Option<String>,
    },
    /// Show one hosting (GET /api/v1/hostings/{id}).
    Get { id: String },
    /// Create a hosting (POST /api/v1/hostings).
    Create {
        #[arg(long)]
        domain: String,
        /// PHP version: 8.3 (or the wire form v8_3).
        #[arg(long)]
        php: Option<String>,
        /// Database engine (mariadb | postgres).
        #[arg(long)]
        db: Option<String>,
        /// Extra domain (repeatable).
        #[arg(long = "alias", value_name = "DOMAIN")]
        aliases: Vec<String>,
        /// Target node id (default: the master).
        #[arg(long)]
        node: Option<String>,
    },
    /// Suspend a hosting.
    Suspend { id: String },
    /// Resume a hosting.
    Resume { id: String },
    /// Switch a hosting's PHP version (PATCH /api/v1/hostings/{id}/php).
    Php {
        id: String,
        /// 8.1 | 8.2 | 8.3 | 8.4
        version: String,
    },
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
        /// Don't ask for confirmation.
        #[arg(long, short)]
        yes: bool,
    },
    /// Run a backup now (async job).
    Backup {
        id: String,
        #[arg(long)]
        wait: bool,
    },
    /// List a hosting's backups.
    Backups { id: String },
    /// Restore a backup (async job). Name it by --backup-id or --archive.
    Restore {
        id: String,
        /// Backup id from `remote backups`.
        #[arg(long, conflicts_with = "archive", required_unless_present = "archive")]
        backup_id: Option<i64>,
        /// Archive path from `remote backups`.
        #[arg(long)]
        archive: Option<String>,
        /// files_and_db | db_only | files_only
        #[arg(long, default_value = "files_and_db")]
        mode: String,
        #[arg(long)]
        wait: bool,
        /// Don't ask for confirmation.
        #[arg(long, short)]
        yes: bool,
    },
    /// Issue an ACME certificate (async job).
    Cert {
        id: String,
        #[arg(long)]
        staging: bool,
        #[arg(long)]
        wait: bool,
    },
    /// Renew every expiring certificate (async job).
    RenewAll {
        #[arg(long)]
        wait: bool,
    },
    /// Poll a background job (GET /api/v1/jobs/{id}).
    Job {
        id: String,
        /// Follow it to completion.
        #[arg(long)]
        wait: bool,
    },
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

/// `8.3` → `v8_3`, the API's wire form; the wire form passes through.
fn php_wire(v: &str) -> String {
    if v.starts_with('v') {
        v.to_string()
    } else {
        format!("v{}", v.replace('.', "_"))
    }
}

/// A path segment with everything but unreserved characters escaped, so an
/// id or domain can never add a path component or a query.
fn seg(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
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
        RemoteCmd::Me => get(&c, "/api/v1/me", &[]).await,
        RemoteCmd::List {
            state,
            node,
            q,
            limit,
            cursor,
        } => {
            let limit = limit.map(|l| l.to_string());
            let query: Vec<(&str, &str)> = [
                ("state", state.as_deref()),
                ("node", node.as_deref()),
                ("q", q.as_deref()),
                ("limit", limit.as_deref()),
                ("cursor", cursor.as_deref()),
            ]
            .into_iter()
            .filter_map(|(k, v)| v.map(|v| (k, v)))
            .collect();
            get(&c, "/api/v1/hostings", &query).await
        }
        RemoteCmd::Get { id } => get(&c, &format!("/api/v1/hostings/{}", seg(id)), &[]).await,
        RemoteCmd::Create {
            domain,
            php,
            db,
            aliases,
            node,
        } => {
            let mut body = json!({ "domain": domain });
            if let Some(v) = php {
                body["php_version"] = json!(php_wire(v));
            }
            if let Some(v) = db {
                body["database"] = json!(v);
            }
            if !aliases.is_empty() {
                body["aliases"] = json!(aliases);
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
                &format!("/api/v1/hostings/{}/suspend", seg(id)),
                None,
            )
            .await
        }
        RemoteCmd::Resume { id } => {
            send(
                &c,
                Method::POST,
                &format!("/api/v1/hostings/{}/resume", seg(id)),
                None,
            )
            .await
        }
        RemoteCmd::Php { id, version } => {
            send(
                &c,
                Method::PATCH,
                &format!("/api/v1/hostings/{}/php", seg(id)),
                Some(json!({ "version": php_wire(version) })),
            )
            .await
        }
        RemoteCmd::Delete {
            id,
            keep_user,
            keep_database,
            wait,
            yes,
        } => {
            crate::util::confirm(&format!("Delete hosting {id}?"), *yes)?;
            let path = format!(
                "/api/v1/hostings/{}?keep_user={keep_user}&keep_database={keep_database}",
                seg(id)
            );
            let v = send_value(&c, Method::DELETE, &path, &[], None).await?;
            maybe_wait(&c, &v, *wait).await
        }
        RemoteCmd::Backup { id, wait } => {
            let v = send_value(
                &c,
                Method::POST,
                &format!("/api/v1/hostings/{}/backup", seg(id)),
                &[],
                None,
            )
            .await?;
            maybe_wait(&c, &v, *wait).await
        }
        RemoteCmd::Backups { id } => {
            get(&c, &format!("/api/v1/hostings/{}/backups", seg(id)), &[]).await
        }
        RemoteCmd::Restore {
            id,
            backup_id,
            archive,
            mode,
            wait,
            yes,
        } => {
            let archive_path = match (archive, backup_id) {
                (Some(a), _) => a.clone(),
                (None, Some(bid)) => {
                    let list = send_value(
                        &c,
                        Method::GET,
                        &format!("/api/v1/hostings/{}/backups", seg(id)),
                        &[],
                        None,
                    )
                    .await?;
                    list.get("items")
                        .and_then(|i| i.as_array())
                        .and_then(|items| {
                            items
                                .iter()
                                .find(|b| b.get("id").and_then(|v| v.as_i64()) == Some(*bid))
                        })
                        .and_then(|b| b.get("archive_path").and_then(|p| p.as_str()))
                        .map(str::to_string)
                        .with_context(|| {
                            format!("{id} has no backup #{bid} with a local archive")
                        })?
                }
                (None, None) => bail!("pass --backup-id or --archive"),
            };
            crate::util::confirm(
                &format!("Restore {archive_path} over the live site {id}?"),
                *yes,
            )?;
            let v = send_value(
                &c,
                Method::POST,
                &format!("/api/v1/hostings/{}/restore", seg(id)),
                &[],
                Some(json!({ "archive_path": archive_path, "mode": mode })),
            )
            .await?;
            maybe_wait(&c, &v, *wait).await
        }
        RemoteCmd::Cert { id, staging, wait } => {
            let body = json!({ "staging": staging });
            let v = send_value(
                &c,
                Method::POST,
                &format!("/api/v1/hostings/{}/cert", seg(id)),
                &[],
                Some(body),
            )
            .await?;
            maybe_wait(&c, &v, *wait).await
        }
        RemoteCmd::RenewAll { wait } => {
            let v = send_value(&c, Method::POST, "/api/v1/certs/renew-all", &[], None).await?;
            maybe_wait(&c, &v, *wait).await
        }
        RemoteCmd::Job { id, wait } => {
            if *wait {
                maybe_wait(&c, &json!({ "job_id": id }), true).await
            } else {
                get(&c, &format!("/api/v1/jobs/{}", seg(id)), &[]).await
            }
        }
        RemoteCmd::Nodes => get(&c, "/api/v1/nodes", &[]).await,
        RemoteCmd::Openapi => get(&c, "/api/v1/openapi.json", &[]).await,
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
async fn get(c: &Conn, path: &str, query: &[(&str, &str)]) -> Result<()> {
    print_and_status(send_value(c, Method::GET, path, query, None).await?)
}

/// Send `method path` with an optional JSON body and print the response.
async fn send(c: &Conn, method: Method, path: &str, body: Option<Value>) -> Result<()> {
    print_and_status(send_value(c, method, path, &[], body).await?)
}

/// Core request: returns the parsed response, failing on a non-2xx. Query
/// values go through reqwest so they are percent-encoded — `--q "a b"` or
/// a cursor with `&` in it used to corrupt the URL.
async fn send_value(
    c: &Conn,
    method: Method,
    path: &str,
    query: &[(&str, &str)],
    body: Option<Value>,
) -> Result<Value> {
    let mut req = c
        .client
        .request(method.clone(), format!("{}{}", c.base, path))
        .bearer_auth(&c.key);
    if !query.is_empty() {
        req = req.query(query);
    }
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
/// otherwise just print the value. A job that ends in anything but `done`
/// is an error, so `--wait` in a script fails the script.
async fn maybe_wait(c: &Conn, v: &Value, wait: bool) -> Result<()> {
    let job_id = v.get("job_id").and_then(|j| j.as_str());
    match (wait, job_id) {
        (true, Some(id)) => {
            eprintln!("job {id} accepted — polling…");
            let mut last = String::new();
            loop {
                let job = send_value(
                    c,
                    Method::GET,
                    &format!("/api/v1/jobs/{}", seg(id)),
                    &[],
                    None,
                )
                .await?;
                let state = job
                    .get("state")
                    .and_then(|s| s.as_str())
                    .unwrap_or("")
                    .to_string();
                // `progress_pct` — JobView serialises it under that name with no
                // serde rename, so reading "progress" printed 0% for the whole
                // life of every job.
                let progress = job
                    .get("progress_pct")
                    .and_then(|p| p.as_i64())
                    .unwrap_or(0);
                let step = job.get("step_label").and_then(|s| s.as_str()).unwrap_or("");
                let line = format!("{state} {progress}% {step}");
                if line != last {
                    eprintln!("  {line}");
                    last = line;
                }
                if state != "running" {
                    let ok = state == "done";
                    print_and_status(job)?;
                    if !ok {
                        bail!("job {id} ended {state}");
                    }
                    return Ok(());
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
    fn php_versions_map_to_the_wire_form() {
        assert_eq!(php_wire("8.3"), "v8_3");
        assert_eq!(php_wire("v8_4"), "v8_4");
    }

    #[test]
    fn path_segments_are_escaped() {
        assert_eq!(seg("example.com"), "example.com");
        assert_eq!(seg("01J7A8GQX"), "01J7A8GQX");
        assert_eq!(seg("a/../b?x=1"), "a%2F..%2Fb%3Fx%3D1");
    }

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
