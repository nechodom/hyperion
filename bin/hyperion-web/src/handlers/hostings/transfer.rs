//! Move, copy and export between nodes.

use super::*;

/// The request that imports bundle `bundle_id` (on the master's disk by
/// now: exported there, or pulled from a worker) on `target_node`, plus the
/// job-log line describing it.
///
/// A worker downloads it from the master's signed bundle endpoint. The
/// master itself reads it straight off its own disk: going over HTTP to its
/// own public name made a copy onto the master hinge on what that name
/// resolves to on the master (127.0.1.1, a private address, a split-horizon
/// answer, nothing inside the agent), and the import-from-URL address check
/// refused the job at 65%.
pub(super) async fn bundle_import_request(
    state: &SharedState,
    target_node: &str,
    bundle_id: &str,
    master_url: &str,
    bundle_ttl: i64,
    override_domain: Option<String>,
) -> (Request, String) {
    if crate::dispatcher::remote_target(state, Some(target_node))
        .await
        .is_none()
    {
        return (
            Request::HostingImportLocalBundle {
                bundle_id: bundle_id.to_string(),
                override_domain,
                override_aliases: Vec::new(),
            },
            format!("bundle_id={bundle_id} (read from the master's own disk)\n"),
        );
    }
    let exp = hyperion_types::now_secs() + bundle_ttl;
    let token = hyperion_auth::bundle_sig::mint(state.csrf_key.as_ref(), bundle_id, exp);
    let base_url = format!("{master_url}/api/migration/bundle/{bundle_id}");
    let log = format!("base_url={base_url}\n");
    (
        Request::HostingImportFromUrl {
            base_url,
            token,
            override_domain,
            override_aliases: Vec::new(),
            // Built above from our own address to our own bundle endpoint.
            master_minted: true,
        },
        log,
    )
}

/// Pull the two bundle files (manifest.json + archive.tar.gz) off
/// a worker source via signed RPC and write them under the master's
/// own /var/lib/hyperion/migration/<bundle_id>/. After this the
/// master's existing /api/migration/bundle/<id>/<filename> route
/// serves the right bytes to the target node — the target doesn't
/// need to know the bundle started life on a worker.
///
/// Returns the local bundle directory on the master on success.
pub(super) async fn pull_bundle_from_worker(
    state: &SharedState,
    source_node: &str,
    bundle_id: &str,
) -> Result<std::path::PathBuf, String> {
    use std::os::unix::fs::PermissionsExt;
    // The bundle id comes back from the (possibly compromised) source worker
    // and is joined onto a root path that is then create_dir_all'd, chmod'd
    // 0700, written into and, on failure, remove_dir_all'd. Validate its shape
    // here, before any of those sinks, so a reply like "../.." or an absolute
    // path can never steer a root filesystem operation. The download route and
    // the Drop guard enforce the same shape; see `is_bundle_id`.
    if !is_bundle_id(bundle_id) {
        return Err(format!("worker returned an invalid bundle id {bundle_id:?}"));
    }
    let root = std::path::Path::new("/var/lib/hyperion/migration");
    let local_dir = root.join(bundle_id);
    tokio::fs::create_dir_all(&local_dir)
        .await
        .map_err(|e| format!("create local bundle dir: {e}"))?;
    // 0700 on the bundle dir AND its parent, as the agent does for its own
    // exports: the bundle is the site's whole tree, database dump and
    // wp-config included. hyperion-web runs as root with the default umask,
    // so these came out 0755/0644 — readable by every tenant on the master
    // for the week the bundle is kept.
    let p700 = std::fs::Permissions::from_mode(0o700);
    let _ = tokio::fs::set_permissions(root, p700.clone()).await;
    tokio::fs::set_permissions(&local_dir, p700)
        .await
        .map_err(|e| format!("lock local bundle dir: {e}"))?;
    let result = pull_bundle_files(state, source_node, bundle_id, &local_dir).await;
    if result.is_err() {
        // A half-pulled bundle is useless and holds site data — drop it.
        let _ = tokio::fs::remove_dir_all(&local_dir).await;
    }
    result.map(|()| local_dir)
}

/// Give the hosting `to` the same per-user access grants `from` has.
///
/// An import always mints a new hosting id and grants are keyed by id, so a
/// customer whose site was moved (or who copied their own site) could see
/// only the suspended original and got a 403 on the live copy. Returns a
/// line for the job log; a failure is reported there, never fatal — the
/// site itself has landed.
pub(super) async fn carry_access_grants(state: &SharedState, from: &str, to: &str) -> String {
    let grants = match hyperion_rpc_client::call(
        &state.agent_socket,
        Request::WebListHostingAccess {
            hosting_id: from.to_string(),
        },
    )
    .await
    {
        Ok(RpcResponse::WebListHostingAccess(g)) => g,
        Ok(RpcResponse::Error(e)) => return format!("access grants NOT carried over: {e}\n"),
        Ok(_) => return "access grants NOT carried over: unexpected response\n".into(),
        Err(e) => return format!("access grants NOT carried over: {e}\n"),
    };
    let mut failed = Vec::new();
    for g in &grants {
        let ok = matches!(
            hyperion_rpc_client::call(
                &state.agent_socket,
                Request::WebGrantHostingAccess {
                    user_id: g.user_id,
                    hosting_id: to.to_string(),
                    level: g.level.clone(),
                    granted_by: g.granted_by,
                },
            )
            .await,
            Ok(RpcResponse::WebGrantHostingAccess)
        );
        if !ok {
            failed.push(g.username.clone());
        }
    }
    if failed.is_empty() {
        format!("access grants carried over: {}\n", grants.len())
    } else {
        format!(
            "access grants carried over: {} — FAILED for {} (grant them on the new site)\n",
            grants.len() - failed.len(),
            failed.join(", ")
        )
    }
}

/// Master-side `hosting_kv` keys that describe the SITE and are keyed by its
/// id on the master whichever node runs it: the operator's notes and tags,
/// and the panel's copy of the `.user.ini` values (the file itself travels
/// in the archive). Everything else in the master's kv is node state, which
/// the bundle carries or deliberately leaves.
pub(super) fn is_master_site_kv(key: &str) -> bool {
    // `php.mem_auto*` and `php.workers_full` share the prefix but are node
    // state on the owning node; the bundle handles them.
    matches!(key, "notes" | "tags")
        || (key.starts_with("php.")
            && !key.starts_with("php.mem_auto")
            && key != "php.workers_full")
}

/// Give the hosting `to` the master-side notes, tags and PHP-ini copy `from`
/// has — same reason as [`carry_access_grants`]: an import mints a new id,
/// and these are keyed by it. One job-log line; never fatal.
pub(super) async fn carry_master_kv(state: &SharedState, from: &str, to: &str) -> String {
    let pairs = match hyperion_rpc_client::call(
        &state.agent_socket,
        Request::HostingKvList {
            hosting_id: from.to_string(),
        },
    )
    .await
    {
        Ok(RpcResponse::HostingKvList(v)) => v,
        Ok(RpcResponse::Error(e)) => {
            return format!("notes, tags, PHP settings NOT carried: {e}\n")
        }
        Ok(_) => return "notes, tags, PHP settings NOT carried: unexpected response\n".into(),
        Err(e) => return format!("notes, tags, PHP settings NOT carried: {e}\n"),
    };
    let mut carried = 0usize;
    let mut failed = Vec::new();
    for (key, value) in pairs.into_iter().filter(|(k, _)| is_master_site_kv(k)) {
        let ok = matches!(
            hyperion_rpc_client::call(
                &state.agent_socket,
                Request::HostingKvSet {
                    hosting_id: to.to_string(),
                    key: key.clone(),
                    value,
                },
            )
            .await,
            Ok(RpcResponse::HostingKvSet)
        );
        if ok {
            carried += 1;
        } else {
            failed.push(key);
        }
    }
    match (carried, failed.is_empty()) {
        (0, true) => String::new(),
        (n, true) => format!("notes, tags, PHP settings carried: {n}\n"),
        (n, false) => format!(
            "notes, tags, PHP settings carried: {n} — FAILED for {}\n",
            failed.join(", ")
        ),
    }
}

/// The importer's per-setting report as job-log lines.
pub(super) fn carry_report_text(lines: &[String]) -> String {
    lines.iter().map(|l| format!("{l}\n")).collect()
}

/// The master's copy of a bundle pulled off a worker, removed when the job
/// is done with it — success or failure. It is a real copy (the source's own
/// export is a hardlink of its backup), so leaving it meant a week of master
/// disk holding the site's data; a retry exports a fresh bundle anyway.
pub(super) struct PulledBundle(pub(super) String);

/// A legal migration bundle id: `mig_` followed by a 26-char alphanumeric
/// ULID. The id is attacker-influenced (a worker reply, a request path), so
/// every site that joins it onto `/var/lib/hyperion/migration` as root must
/// gate on this first. Shared by `pull_bundle_from_worker`, the download
/// route (migration.rs) and the `PulledBundle` Drop guard.
pub(super) fn is_bundle_id(id: &str) -> bool {
    id.len() == 4 + 26
        && id.starts_with("mig_")
        && id[4..].chars().all(|c| c.is_ascii_alphanumeric())
}

impl Drop for PulledBundle {
    fn drop(&mut self) {
        let id = std::mem::take(&mut self.0);
        // Same shape check as the download route: never join an arbitrary id.
        if is_bundle_id(&id) {
            let dir = std::path::Path::new("/var/lib/hyperion/migration").join(id);
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

/// The files of one worker bundle → `local_dir`, each fetched in slices.
///
/// One RPC per file used to carry the whole archive base64'd in a single
/// response, which the remote client's 192 MiB response cap (and the 30 s
/// default timeout) cut off for any site over ~144 MiB: "Bundle proxy
/// failed" for every ordinary WordPress site on a worker.
pub(super) async fn pull_bundle_files(
    state: &SharedState,
    source_node: &str,
    bundle_id: &str,
    local_dir: &std::path::Path,
) -> Result<(), String> {
    use base64::Engine;
    use tokio::io::AsyncWriteExt;
    const CHUNK: u32 = 8 * 1024 * 1024;
    let mut files = vec!["manifest.json", "archive.tar.gz"];
    let mut idx = 0;
    while idx < files.len() {
        let filename = files[idx];
        idx += 1;
        let dest = local_dir.join(filename);
        let mut out = tokio::fs::File::create(&dest)
            .await
            .map_err(|e| format!("create {filename}: {e}"))?;
        let mut offset: u64 = 0;
        loop {
            let resp = crate::dispatcher::dispatch_to_node(
                state,
                Some(source_node),
                Request::HostingMigrationFetchBundleFile {
                    bundle_id: bundle_id.to_string(),
                    filename: filename.to_string(),
                    offset,
                    len: CHUNK,
                },
            )
            .await
            .map_err(|e| format!("rpc {filename}: {e}"))?;
            let (bytes_b64, total_size, eof) = match resp {
                RpcResponse::HostingMigrationFetchBundleFile {
                    bytes_b64,
                    total_size,
                    eof,
                } => (bytes_b64, total_size, eof),
                RpcResponse::Error(e) => return Err(format!("source rejected {filename}: {e}")),
                _ => return Err(format!("unexpected response for {filename}")),
            };
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(bytes_b64.as_bytes())
                .map_err(|e| format!("b64 {filename}: {e}"))?;
            out.write_all(&bytes)
                .await
                .map_err(|e| format!("write {filename}: {e}"))?;
            offset += bytes.len() as u64;
            // total_size 0 = an agent that predates slicing: it sent the
            // whole file in this one response.
            if eof || total_size == 0 || bytes.is_empty() {
                if total_size != 0 && offset != total_size {
                    return Err(format!(
                        "{filename} came back short: {offset} of {total_size} bytes"
                    ));
                }
                break;
            }
        }
        out.flush()
            .await
            .map_err(|e| format!("flush {filename}: {e}"))?;
        // The database dump travels only when the manifest says there is
        // one — the importer refuses a DB site whose bundle lacks it.
        if filename == "manifest.json" {
            let has_dump = tokio::fs::read(&dest)
                .await
                .ok()
                .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
                .is_some_and(|v| v.get("db_dump_sha256").is_some_and(|d| d.is_string()));
            if has_dump {
                files.push(hyperion_types::HostingMigrationManifest::DB_DUMP_FILE);
            }
        }
    }
    Ok(())
}

#[derive(Template)]
#[template(path = "hosting_transfer.html")]
pub(super) struct TransferTpl<'a> {
    pub(super) username: &'a str,
    pub(super) user_initial: char,
    pub(super) active: &'static str,
    pub(super) css_version: &'static str,
    pub(super) htmx_version: &'static str,
    pub(super) detail: hyperion_types::HostingDetail,
    /// node_id the hosting currently lives on ("" = master).
    pub(super) target_node: String,
    pub(super) all_nodes: Vec<hyperion_types::NodeSummary>,
    pub(super) csrf_token: String,
}

/// GET /hostings/transfer/<selector>
///
/// The unified "Move or copy a site" wizard. One guided page that replaces the
/// three scattered cards (one-click migrate / clone / manual export) that used
/// to live in the detail Migration tab. The three modes still POST to the same
/// existing endpoints (`/hostings/migration/move`, `/hostings/clone`,
/// `/hostings/migration/export`) — this is a front-end unification only.
pub async fn get_transfer(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Path(selector): Path<String>,
) -> Result<Response, AppError> {
    let sel = parse_selector(&selector)?;
    let (detail, owner_node) = find_hosting_anywhere(&state, sel).await?;
    // Moving/copying is a manage action — read-only users don't get the wizard.
    if let Err(r) = require_hosting_access(
        &state,
        &ctx,
        detail.id.as_str(),
        true,
        Capability::HostingView,
    )
    .await
    {
        return Ok(r);
    }
    let all_nodes = fetch_remote_nodes(&state).await.unwrap_or_default();
    let tpl = TransferTpl {
        username: &ctx.username,
        user_initial: crate::handlers::user_initial(&ctx.username),
        active: "hostings",
        css_version: crate::handlers::css_version(),
        htmx_version: crate::handlers::htmx_version(),
        target_node: owner_node.unwrap_or_default(),
        all_nodes,
        detail,
        csrf_token: crate::handlers::session_csrf_token(&state, &ctx),
    };
    Ok(Html(tpl.render()?).into_response())
}

/// POST /hostings/migration/export
///
/// Trigger a migration-bundle export on the source node. Returns a
/// redirect to the detail page with the bundle paths flashed —
/// operator copies the scp one-liner from there. The bundle stays on
/// disk until the operator deletes it (no auto-prune for now).
#[derive(Deserialize)]
pub struct MigrationExportForm {
    pub selector: String,
}

/// Template for the one-shot "export result" page rendered inline as
/// the POST response (NOT a redirect — the URL would otherwise carry
/// the signed token through browser history and the Referer header).
#[derive(Template)]
#[template(path = "migration_export_result.html")]
pub(super) struct MigrationExportResultTpl<'a> {
    pub(super) username: &'a str,
    pub(super) user_initial: char,
    pub(super) active: &'static str,
    pub(super) css_version: &'static str,
    pub(super) htmx_version: &'static str,
    pub(super) selector: &'a str,
    pub(super) bundle: hyperion_types::HostingMigrationBundle,
    /// Session-wide CSRF token. Currently unread by the template
    /// itself (no forms on the result page), but populated so a
    /// future "delete bundle now" or "regenerate token" button can
    /// drop in without re-plumbing the handler.
    #[allow(dead_code)]
    pub(super) csrf_token: String,
}

/// One-click migration: export the hosting from its current node,
/// hand the signed download URL to the target node, wait for the
/// import to finish. After success, the OLD hosting is suspended
/// (NOT deleted — operator should verify the new one before
/// pulling the trigger).
///
/// Current limitation: only works when the SOURCE is the master.
/// Worker-to-worker / worker-to-master needs the master to proxy
/// the bundle bytes (each worker holds its own /var/lib/hyperion/
/// migration/<id>/ — only master serves the /api/migration/bundle/
/// route). That's a follow-up.
#[derive(Deserialize)]
pub struct MigrationMoveForm {
    pub selector: String,
    pub target_node: String,
    /// Hidden — populated by the JS-injected hidden input. Identifies
    /// which node the hosting currently LIVES on (source).
    #[serde(default)]
    pub source_node: String,
}

/// Form input for "Clone this hosting to a new domain (and
/// optionally a different node)". Renders into the cross-node
/// migration tracker so the operator gets a live progress bar.
#[derive(serde::Deserialize)]
pub struct HostingCloneForm {
    /// Source hosting selector (domain or id, same shape as
    /// migrate uses).
    pub selector: String,
    /// New domain for the clone — e.g. `staging.example.cz`.
    pub new_domain: String,
    /// Optional target node. Empty / `LOCAL_NODE_SENTINEL` ⇒ clone
    /// on the master itself (single-node deploy or staging clone
    /// next to the original).
    #[serde(default)]
    pub target_node: String,
    /// Hidden — populated by the page so the source-node dispatch
    /// matches the original migration form.
    #[serde(default)]
    pub source_node: String,
    /// When set, try to issue an HTTPS (Let's Encrypt HTTP-01) certificate for
    /// `new_domain` once the clone lands — but ONLY if the domain's DNS already
    /// resolves to the target node. A miss is not a failure; it's reported and
    /// the operator can issue later from the SSL tab.
    #[serde(default)]
    pub issue_cert: bool,
    /// Also serve the copy on `www.<new_domain>`. A Copy never carries the
    /// source's aliases (they name the SOURCE), so without this a copy put
    /// under a live domain answered the bare name only, and every visitor on
    /// `www.` got the node's "No site here yet" page. Honoured only where a
    /// `www.` makes sense — see [`clone_www_alias`].
    #[serde(default)]
    pub add_www: bool,
}

/// The copy's domain as typed → the bare lowercase domain the importer
/// needs. Forgives what a paste from the address bar carries (`https://`,
/// a trailing `/` or path, a `:port`) and refuses anything that still isn't
/// a domain, with a message fit for the clone card.
///
/// A leading `www.` goes too: `create` folds it into the bare name anyway,
/// so checking `www.example.cz` for duplicates (and labelling the job with
/// it) while the hosting lands as `example.cz` would check the wrong name.
pub(super) fn clone_domain_from_input(raw: &str) -> Result<String, String> {
    hyperion_validate::Domain::parse(clone_typed_host(raw))
        .map(|d| d.without_www().into_inner())
        .map_err(|_| format!("\"{}\" is not a valid domain for the copy.", raw.trim()))
}

/// The host part of what was typed into the copy's domain field.
pub(super) fn clone_typed_host(raw: &str) -> &str {
    let s = raw.trim();
    let s = s
        .strip_prefix("https://")
        .or_else(|| s.strip_prefix("http://"))
        .unwrap_or(s);
    let host = s.split(['/', '?', '#']).next().unwrap_or_default();
    host.split(':').next().unwrap_or_default()
}

/// The `www.` alias the copy gets, if any. `bare` is
/// [`clone_domain_from_input`]'s answer for `raw`.
///
/// Asked for (`wanted`) AND either typed with its `www.` — the operator
/// pasted the live address — or a two-label name like `example.cz`. A
/// staging subdomain gets none: `www.staging.example.cz` resolves nowhere,
/// and an alias without DNS keeps the certificate from being issued.
pub(super) fn clone_www_alias(raw: &str, bare: &str, wanted: bool) -> Option<String> {
    if !wanted {
        return None;
    }
    let typed_www =
        hyperion_validate::Domain::parse(clone_typed_host(raw)).is_ok_and(|d| d.as_str() != bare);
    let two_labels = bare.split('.').count() == 2;
    (typed_www || two_labels).then(|| format!("www.{bare}"))
}

pub async fn post_hosting_clone(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    headers: axum::http::HeaderMap,
    Form(form): Form<HostingCloneForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(
        &state,
        &ctx,
        &form.selector,
        Capability::HostingMigrateClone,
    )
    .await
    {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let sel_url = urlencoding(&form.selector);
    let refuse = |msg: &str| {
        Ok(Redirect::to(&format!(
            "/hostings/{}?flash_error={}#clone",
            sel_url,
            urlencoding(msg)
        ))
        .into_response())
    };
    // A copy is a brand-new hosting. The built-in Customer role holds
    // HostingMigrateClone but deliberately not HostingCreate, so gating on
    // the former alone let a customer mint sites on any node.
    if !ctx.can(Capability::HostingCreate) {
        return refuse("Copying a site creates a new hosting, which your role cannot do.");
    }

    // ── Sanity gates ──
    if form.new_domain.trim().is_empty() {
        return Ok(Redirect::to(&format!(
            "/hostings/{}?flash_error=Enter+a+domain+for+the+copy#clone",
            sel_url
        ))
        .into_response());
    }
    // Refuse a bad domain HERE, before the job exports a multi-GB bundle —
    // the agent only parses it after the export, and `www.example.cz/`
    // pasted from the address bar used to ride all the way to the import.
    let new_domain = match clone_domain_from_input(&form.new_domain) {
        Ok(d) => d,
        Err(msg) => {
            return Ok(Redirect::to(&format!(
                "/hostings/{}?flash_error={}#clone",
                sel_url,
                urlencoding(&msg)
            ))
            .into_response());
        }
    };
    // Where the source lives and what it is called, from the cluster — not
    // from the page. The form posts the hosting's ULID as `selector`, so
    // comparing the new domain against it never matched, and the hidden
    // `source_node` is only as current as the page (a Retry replays it).
    let (source, source_owner) = match find_hosting_anywhere(&state, sel.clone()).await {
        Ok(v) => v,
        Err(_) => return refuse("The source hosting could not be found."),
    };
    if new_domain.eq_ignore_ascii_case(&source.domain) {
        return refuse("Clone domain must differ from the source domain.");
    }
    // A domain already live anywhere in the cluster: two vhosts for one
    // name, whichever node DNS points at answers. On the same node the agent
    // would refuse too — but only after the whole export had run.
    match list_hostings(&state).await {
        Ok(rows) => {
            if let Some(dup) = rows
                .iter()
                .find(|r| r.domain.eq_ignore_ascii_case(&new_domain))
            {
                let where_ = match dup.node_id.as_deref() {
                    Some(crate::dispatcher::LOCAL_NODE_SENTINEL) | None => {
                        "the master node".to_string()
                    }
                    Some(n) => format!("node {n}"),
                };
                return refuse(&format!(
                    "A hosting for {} already exists on {where_}. Pick a different domain.",
                    dup.domain
                ));
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, domain = %new_domain,
                "clone: cluster duplicate-domain check skipped (list failed) — proceeding");
        }
    }

    let source_local = source_owner.is_none();
    let source_node_str =
        source_owner.unwrap_or_else(|| crate::dispatcher::LOCAL_NODE_SENTINEL.to_string());
    // Default target_node = source when empty so single-node deploys
    // can clone in place.
    let target_node_str = if form.target_node.trim().is_empty() {
        source_node_str.clone()
    } else {
        form.target_node.trim().to_string()
    };

    // Reuse the migration job pattern — same kind="hosting_clone"
    // bucket so /jobs shows them under their own filter row.
    let master_url = crate::handlers::derive_master_url(&state, &headers).await;
    let bundle_ttl = crate::handlers::migration::BUNDLE_DOWNLOAD_TTL_SECS;
    let www_alias = clone_www_alias(&form.new_domain, &new_domain, form.add_www);
    let payload = serde_json::json!({
        "selector": form.selector,
        "new_domain": new_domain,
        "www_alias": www_alias,
        "source_node": source_node_str,
        "target_node": target_node_str,
        "issue_cert": form.issue_cert,
    });
    let actor_uid = ctx.session.as_ref().map(|s| s.user_id).unwrap_or(0);
    let actor_label = ctx.username.clone();
    let clone_state = state.clone();
    let clone_sel = sel.clone();
    let clone_form_sel = form.selector.clone();
    let clone_source = source_node_str.clone();
    let clone_target = target_node_str.clone();
    let clone_new_domain = new_domain.clone();
    let clone_issue_cert = form.issue_cert;

    let job_id = crate::handlers::jobs::spawn_job(
        state.clone(),
        "hosting_clone",
        Some(&new_domain),
        &payload.to_string(),
        &actor_label,
        actor_uid,
        move |reporter| async move {
            run_clone_job(
                reporter,
                clone_state,
                clone_sel,
                clone_form_sel,
                source_local,
                clone_source,
                clone_target,
                clone_new_domain,
                www_alias,
                master_url,
                bundle_ttl,
                clone_issue_cert,
            )
            .await;
        },
    )
    .await?;

    Ok(Redirect::to(&format!("/jobs/{}", job_id)).into_response())
}

/// Background worker for hosting clone. Same shape as
/// `run_migration_job` but:
///   * does NOT suspend the source (clones are an additive op —
///     the original keeps serving traffic)
///   * passes `override_domain` so the importer creates the new
///     hosting under `new_domain` instead of the manifest's
///     captured domain
///   * surfaces the new domain in the final step label so the
///     operator can click it from the job page.
#[allow(clippy::too_many_arguments)]
pub(super) async fn run_clone_job(
    reporter: crate::handlers::jobs::JobReporter,
    state: SharedState,
    sel: hyperion_rpc::HostingSelector,
    selector_text: String,
    source_local: bool,
    source_node: String,
    target_node: String,
    new_domain: String,
    www_alias: Option<String>,
    master_url: String,
    bundle_ttl: i64,
    issue_cert: bool,
) {
    let source_dispatch = if source_local {
        None
    } else {
        Some(source_node.as_str())
    };

    // ---- 0. Version preflight (see run_migration_job for the
    //         rationale; same cryptic curl bug bit clones too). ----
    reporter
        .step("Pre-flight: version check on source + target", 2, "")
        .await;
    let master_v = probe_agent_version(&state, None).await;
    let src_v = probe_agent_version(&state, source_dispatch).await;
    let tgt_v = probe_agent_version(&state, Some(target_node.as_str())).await;
    if src_v != master_v || tgt_v != master_v {
        reporter
            .finish(
                false,
                Some(format!(
                    "agent version mismatch — master {master_v}, source {src_v}, target {tgt_v}. \
                     Update the lagging node via /install#node-{target_node} before re-running clone."
                )),
            )
            .await;
        return;
    }
    reporter
        .step(
            "Pre-flight: versions match",
            4,
            &format!("master={master_v} source={src_v} target={tgt_v}\n"),
        )
        .await;

    reporter
        .step(
            &format!(
                "Exporting source bundle on {}",
                if source_local {
                    "master"
                } else {
                    source_node.as_str()
                }
            ),
            5,
            &format!("source selector: {}\n", selector_text),
        )
        .await;
    let export = match crate::dispatcher::dispatch_to_node(
        &state,
        source_dispatch,
        Request::HostingExport {
            hosting: sel.clone(),
        },
    )
    .await
    {
        Ok(v) => v,
        Err(e) => {
            reporter
                .finish(false, Some(format!("dispatch HostingExport: {e}")))
                .await;
            return;
        }
    };
    let bundle = match export {
        RpcResponse::HostingExport(b) => b,
        RpcResponse::Error(e) => {
            reporter
                .finish(false, Some(format!("Export failed: {e}")))
                .await;
            return;
        }
        _ => {
            reporter
                .finish(false, Some("expected HostingExport response".into()))
                .await;
            return;
        }
    };
    reporter
        .step(
            "Bundle ready on source",
            30,
            &format!(
                "bundle_id={} archive_bytes={}\n",
                bundle.bundle_id, bundle.archive_bytes
            ),
        )
        .await;

    // Lives to the end of the job: the pulled copy goes on every exit.
    let _pulled = (!source_local).then(|| PulledBundle(bundle.bundle_id.clone()));
    if !source_local {
        reporter
            .step("Proxying bundle from worker to master", 45, "")
            .await;
        if let Err(e) = pull_bundle_from_worker(&state, &source_node, &bundle.bundle_id).await {
            reporter
                .finish(false, Some(format!("Bundle proxy failed: {e}")))
                .await;
            return;
        }
        reporter
            .step("Bundle landed on master", 55, "proxy ok\n")
            .await;
    } else {
        reporter
            .step("Bundle already on master (source was local)", 55, "")
            .await;
    }

    let (import_req, import_log) = bundle_import_request(
        &state,
        &target_node,
        &bundle.bundle_id,
        &master_url,
        bundle_ttl,
        Some(new_domain.clone()),
    )
    .await;
    reporter
        .step(
            &format!("Importing as {} on {}", new_domain, target_node),
            65,
            &format!("override_domain={new_domain}\n{import_log}"),
        )
        .await;
    let import =
        match crate::dispatcher::dispatch_to_node(&state, Some(target_node.as_str()), import_req)
            .await
        {
            Ok(v) => v,
            Err(e) => {
                reporter
                    .finish(false, Some(format!("dispatch bundle import: {e}")))
                    .await;
                return;
            }
        };
    // The domain the target actually created — `create` folds a typed
    // `www.` into the bare name, so the cert and the final link use this.
    let (new_id, new_domain, carry_report) = match import {
        RpcResponse::HostingImportFromUrl(r) | RpcResponse::HostingImportLocalBundle(r) => {
            (r.new_hosting_id, r.domain, r.carry_report)
        }
        RpcResponse::Error(e) => {
            reporter
                .finish(false, Some(format!("Target import failed: {e}")))
                .await;
            return;
        }
        _ => {
            reporter
                .finish(false, Some("expected a bundle import response".into()))
                .await;
            return;
        }
    };
    let grants_note =
        carry_access_grants(&state, bundle.source_hosting_id.as_str(), new_id.as_str()).await;
    let kv_note = carry_master_kv(&state, bundle.source_hosting_id.as_str(), new_id.as_str()).await;
    reporter
        .step(
            &format!("Imported as {new_domain}"),
            80,
            &format!("{grants_note}{kv_note}{}", carry_report_text(&carry_report)),
        )
        .await;

    tracing::info!(
        source = %selector_text,
        target_node = %target_node,
        new_domain = %new_domain,
        new_hosting_id = new_id.as_str(),
        "hosting clone completed"
    );

    // ---- Optional: the `www.` alias and an HTTPS cert for the new domain ----
    // HTTP-01 needs the domain to resolve to the TARGET node, so we gate on a
    // DnsCheck against that node first. A miss (DNS not pointed yet) is NOT a
    // clone failure — we note it and the operator can issue later from the SSL
    // tab once DNS propagates. Dispatched to the target node (where the site +
    // its nginx now live).
    let names_note = finish_clone_names(
        &state,
        &target_node,
        &new_id,
        &new_domain,
        www_alias.is_some(),
        issue_cert,
        &reporter,
    )
    .await;

    reporter
        .step(
            &format!(
                "Done — clone live at {} (id {}) on {}{}",
                new_domain,
                new_id.as_str(),
                target_node,
                names_note
            ),
            100,
            "clone ok\n",
        )
        .await;
    reporter.finish(true, None).await;
}

/// The copy's `www.` alias and HTTPS certificate. Returns a suffix for the
/// final job step. Never fails the clone — every branch adds a note instead.
///
/// The alias goes on after the import, not inside it: a name already taken
/// on the target would otherwise fail the whole import after the bundle was
/// exported and downloaded. Here it costs only the alias. Derived from the
/// domain that landed, since `create` may have folded the typed one.
///
/// DNS decides the order. The certificate names every alias, and HTTP-01
/// for a name that does not reach the target fails the whole order — so a
/// `www.` whose DNS is not here yet goes on AFTER a certificate for the bare
/// name, served (behind a name warning) until the operator reissues.
pub(super) async fn finish_clone_names(
    state: &SharedState,
    target_node: &str,
    new_id: &hyperion_types::HostingId,
    new_domain: &str,
    want_www: bool,
    issue_cert: bool,
    reporter: &crate::handlers::jobs::JobReporter,
) -> String {
    let www = want_www.then(|| format!("www.{new_domain}"));
    let mut note = String::new();
    let cert_dns = if issue_cert {
        reporter
            .step(
                &format!("Checking DNS for {new_domain} before issuing HTTPS"),
                85,
                "",
            )
            .await;
        Some(clone_dns_points_here(state, target_node, new_domain).await)
    } else {
        None
    };
    let www_reaches = match (&cert_dns, &www) {
        (Some(Ok(_)), Some(w)) => clone_dns_points_here(state, target_node, w).await.is_ok(),
        _ => false,
    };
    let alias_after_cert = matches!(cert_dns, Some(Ok(_))) && www.is_some() && !www_reaches;
    if let (Some(w), false) = (&www, alias_after_cert) {
        note += &add_clone_www(state, target_node, new_id, w, reporter)
            .await
            .1;
    }
    match cert_dns {
        Some(Ok(dns_note)) => {
            note += &issue_clone_cert(state, target_node, new_id, new_domain, &dns_note, reporter)
                .await;
        }
        Some(Err(skip)) => note += &skip,
        None => {}
    }
    if let (Some(w), true) = (&www, alias_after_cert) {
        let (added, added_note) = add_clone_www(state, target_node, new_id, w, reporter).await;
        note += &added_note;
        if added {
            note.push_str(
                " (not in the certificate yet — its DNS doesn't point here; \
                 reissue from the SSL tab once it does)",
            );
        }
    }
    note
}

/// Put `www` on the fresh copy as its alias: whether it is now served, and
/// the note for the job step.
pub(super) async fn add_clone_www(
    state: &SharedState,
    target_node: &str,
    new_id: &hyperion_types::HostingId,
    www: &str,
    reporter: &crate::handlers::jobs::JobReporter,
) -> (bool, String) {
    let Ok(www_dom) = Domain::parse(www) else {
        return (false, format!(" · {www} not added — not a valid name"));
    };
    reporter
        .step(&format!("Adding {www} as an alias"), 88, "")
        .await;
    match crate::dispatcher::dispatch_to_node(
        state,
        Some(target_node),
        Request::HostingSetAliases {
            sel: HostingSelector::Id(new_id.clone()),
            aliases: vec![www_dom],
        },
    )
    .await
    {
        Ok(RpcResponse::HostingSetAliases(_)) => (true, format!(" · also on {www}")),
        Ok(RpcResponse::Error(e)) => (
            false,
            format!(" · {www} not added ({e}) — add it on the site's Domains card"),
        ),
        Ok(_) => (false, format!(" · {www} not added — unexpected response")),
        Err(e) => (false, format!(" · {www} not added — dispatch failed: {e}")),
    }
}

/// Does `name` resolve to the target node? `Ok` = the check's note, `Err` =
/// the job-step note saying why HTTPS was skipped.
pub(super) async fn clone_dns_points_here(
    state: &SharedState,
    target_node: &str,
    name: &str,
) -> Result<String, String> {
    let Ok(domain) = Domain::parse(name) else {
        return Err(format!(" · HTTPS skipped — {name} is not a valid name"));
    };
    match crate::dispatcher::dispatch_to_node(
        state,
        Some(target_node),
        Request::DnsCheck { domain },
    )
    .await
    {
        Ok(RpcResponse::DnsCheck(r)) if r.matches => Ok(r.note),
        Ok(RpcResponse::DnsCheck(r)) => Err(format!(
            " · HTTPS skipped — DNS for {name} doesn't point to this node yet ({}); \
             issue it from the SSL tab once DNS propagates",
            r.note
        )),
        Ok(RpcResponse::Error(e)) => Err(format!(" · HTTPS skipped — DNS check failed: {e}")),
        _ => Err(" · HTTPS skipped — DNS check unavailable".to_string()),
    }
}

/// Issue the copy's HTTPS certificate, its DNS already checked.
pub(super) async fn issue_clone_cert(
    state: &SharedState,
    target_node: &str,
    new_id: &hyperion_types::HostingId,
    new_domain: &str,
    dns_note: &str,
    reporter: &crate::handlers::jobs::JobReporter,
) -> String {
    reporter
        .step(
            &format!("DNS points here — issuing HTTPS certificate for {new_domain}"),
            92,
            &format!("{dns_note}\n"),
        )
        .await;
    // `CertIssueAcme`, not the legacy `CertIssue`: every agent answers
    // that one "not supported", so the ticked-by-default box never
    // issued a certificate.
    match crate::dispatcher::dispatch_to_node(
        state,
        Some(target_node),
        Request::CertIssueAcme {
            sel: HostingSelector::Id(new_id.clone()),
            req: hyperion_types::CertIssueRequest {
                staging: false,
                require_dns_match: false,
                extra_sans: vec![],
            },
        },
    )
    .await
    {
        Ok(RpcResponse::CertIssueAcme(_)) => format!(" · HTTPS issued for {new_domain}"),
        Ok(RpcResponse::Error(e)) => format!(" · HTTPS skipped — issuance failed: {e}"),
        Ok(_) => " · HTTPS skipped — unexpected response".to_string(),
        Err(e) => format!(" · HTTPS skipped — dispatch failed: {e}"),
    }
}

pub async fn post_migration_move(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    headers: axum::http::HeaderMap,
    Form(form): Form<MigrationMoveForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(
        &state,
        &ctx,
        &form.selector,
        Capability::HostingMigrateClone,
    )
    .await
    {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let sel_url = urlencoding(&form.selector);

    // 0. Sanity gates.
    let target = form.target_node.trim();
    if target.is_empty() {
        return Ok(Redirect::to(&format!(
            "/hostings/{}?flash_error=Pick+a+destination+node+first#migration",
            sel_url
        ))
        .into_response());
    }
    // Where the source lives, from the cluster rather than the page's hidden
    // field (a Retry replays the page's value, which a since-moved site
    // makes wrong).
    let source_owner = match find_hosting_anywhere(&state, sel.clone()).await {
        Ok((_, owner)) => owner,
        Err(_) => {
            return Ok(Redirect::to(&format!(
                "/hostings/{}?flash_error={}#migration",
                sel_url,
                urlencoding("The source hosting could not be found.")
            ))
            .into_response())
        }
    };
    let source_local = source_owner.is_none();
    let source_node_str =
        source_owner.unwrap_or_else(|| crate::dispatcher::LOCAL_NODE_SENTINEL.to_string());
    let target_owned = target.to_string();
    if target_owned == source_node_str {
        return Ok(Redirect::to(&format!(
            "/hostings/{}?flash_error={}#migration",
            sel_url,
            urlencoding("Target node must be different from the source.")
        ))
        .into_response());
    }

    // Migration is 30-300 seconds depending on hosting size, with
    // mysqldump + tar + scp + reimport phases. Doing this inline
    // freezes the browser tab with no signal. Hand it to the generic
    // job-tracker: open a `migration` row, tokio::spawn the work,
    // redirect the operator to /jobs/<id> where they watch the live
    // progress bar tick through each phase.
    let master_url = crate::handlers::derive_master_url(&state, &headers).await;
    let bundle_ttl = crate::handlers::migration::BUNDLE_DOWNLOAD_TTL_SECS;
    let payload = serde_json::json!({
        "selector": form.selector,
        "source_node": source_node_str,
        "target_node": target_owned,
    });
    let migration_state = state.clone();
    let migration_sel = sel.clone();
    let migration_form_sel = form.selector.clone();
    let migration_source_node = source_node_str.clone();
    let migration_target = target_owned.clone();
    let actor_label = ctx.username.clone();
    let actor_uid = ctx.session.as_ref().map(|s| s.user_id).unwrap_or(0);

    let job_id = crate::handlers::jobs::spawn_job(
        state.clone(),
        "migration",
        Some(&form.selector),
        &payload.to_string(),
        &actor_label,
        actor_uid,
        move |reporter| async move {
            run_migration_job(
                reporter,
                migration_state,
                migration_sel,
                migration_form_sel,
                source_local,
                migration_source_node,
                migration_target,
                master_url,
                bundle_ttl,
            )
            .await;
        },
    )
    .await?;

    // 200 OK with redirect to the live progress page.
    Ok(Redirect::to(&format!("/jobs/{}", job_id)).into_response())
}

pub(super) async fn probe_agent_version(state: &SharedState, node: Option<&str>) -> String {
    match crate::dispatcher::dispatch_to_node(state, node, Request::AgentInfo).await {
        Ok(RpcResponse::AgentInfo(i)) => i.version,
        _ => String::from("unknown"),
    }
}

pub(super) async fn run_migration_job(
    reporter: crate::handlers::jobs::JobReporter,
    state: SharedState,
    sel: hyperion_rpc::HostingSelector,
    selector_text: String,
    source_local: bool,
    source_node: String,
    target_node: String,
    master_url: String,
    bundle_ttl: i64,
) {
    let source_dispatch = if source_local {
        None
    } else {
        Some(source_node.as_str())
    };

    // ---- 0. Version preflight ----
    //
    // The cross-node migration / clone pipeline calls
    // `curl_to_file` on the TARGET node — if its agent binary
    // is from before bb09ebc, every import dies with a cryptic
    // `curl: option --max-time: expected a proper numerical
    // parameter` ~2 s into the run. The error tail looks
    // identical to the one the master-side fix already cured,
    // so the operator wastes time re-reading their own commit
    // history before realising the worker just wasn't updated.
    //
    // Stop that loop here: probe AgentInfo on source AND
    // target, compare against the master's own version. Any
    // mismatch ⇒ fail-fast with a clean message pointing
    // directly at `/install#node-<id>` where the per-node
    // Update button lives. The operator clicks once and
    // re-runs the migration.
    reporter
        .step("Pre-flight: version check on source + target", 2, "")
        .await;
    let master_v = probe_agent_version(&state, None).await;
    let src_v = probe_agent_version(&state, source_dispatch).await;
    let tgt_v = probe_agent_version(&state, Some(target_node.as_str())).await;
    if src_v != master_v || tgt_v != master_v {
        reporter
            .finish(
                false,
                Some(format!(
                    "agent version mismatch — master {master_v}, source {src_v}, target {tgt_v}. \
                     The cross-node migration curl bug was fixed in commit bb09ebc; \
                     update the lagging node(s) via /install#node-{target_node} \
                     (and the source if it isn't the master) before re-running migration."
                )),
            )
            .await;
        return;
    }
    reporter
        .step(
            "Pre-flight: versions match",
            4,
            &format!("master={master_v} source={src_v} target={tgt_v}\n"),
        )
        .await;

    // ---- 1. Export bundle on source ----
    reporter
        .step(
            &format!(
                "Exporting bundle on {}",
                if source_local {
                    "master"
                } else {
                    source_node.as_str()
                }
            ),
            5,
            "scheduling HostingExport RPC\n",
        )
        .await;
    let export = match crate::dispatcher::dispatch_to_node(
        &state,
        source_dispatch,
        Request::HostingExport {
            hosting: sel.clone(),
        },
    )
    .await
    {
        Ok(v) => v,
        Err(e) => {
            reporter
                .finish(false, Some(format!("dispatch HostingExport: {e}")))
                .await;
            return;
        }
    };
    let bundle = match export {
        RpcResponse::HostingExport(b) => b,
        RpcResponse::Error(e) => {
            reporter
                .finish(false, Some(format!("Export failed: {e}")))
                .await;
            return;
        }
        _ => {
            reporter
                .finish(false, Some("expected HostingExport response".into()))
                .await;
            return;
        }
    };
    reporter
        .step(
            "Bundle ready on source",
            30,
            &format!(
                "bundle_id={} archive_bytes={}\n",
                bundle.bundle_id, bundle.archive_bytes
            ),
        )
        .await;

    // ---- 1b. Pull bundle to master if source was a worker ----
    // Lives to the end of the job: the pulled copy goes on every exit.
    let _pulled = (!source_local).then(|| PulledBundle(bundle.bundle_id.clone()));
    if !source_local {
        reporter
            .step("Proxying bundle from worker to master", 45, "")
            .await;
        if let Err(e) = pull_bundle_from_worker(&state, &source_node, &bundle.bundle_id).await {
            reporter
                .finish(false, Some(format!("Bundle proxy failed: {e}")))
                .await;
            return;
        }
        reporter
            .step("Bundle landed on master", 55, "proxy ok\n")
            .await;
    } else {
        reporter
            .step("Bundle already on master (source was local)", 55, "")
            .await;
    }

    // ---- 2. Signed download URL, or the master's own disk ----
    let (import_req, import_log) = bundle_import_request(
        &state,
        &target_node,
        &bundle.bundle_id,
        &master_url,
        bundle_ttl,
        None,
    )
    .await;

    // ---- 3. Import on target ----
    reporter
        .step(
            &format!("Importing on target {}", target_node),
            65,
            &import_log,
        )
        .await;
    let import =
        match crate::dispatcher::dispatch_to_node(&state, Some(target_node.as_str()), import_req)
            .await
        {
            Ok(v) => v,
            Err(e) => {
                reporter
                    .finish(false, Some(format!("dispatch bundle import: {e}")))
                    .await;
                return;
            }
        };
    let (new_id, carry_report) = match import {
        RpcResponse::HostingImportFromUrl(r) | RpcResponse::HostingImportLocalBundle(r) => {
            (r.new_hosting_id, r.carry_report)
        }
        RpcResponse::Error(e) => {
            reporter
                .finish(false, Some(format!("Target import failed: {e}")))
                .await;
            return;
        }
        _ => {
            reporter
                .finish(false, Some("expected a bundle import response".into()))
                .await;
            return;
        }
    };
    let grants_note =
        carry_access_grants(&state, bundle.source_hosting_id.as_str(), new_id.as_str()).await;
    let kv_note = carry_master_kv(&state, bundle.source_hosting_id.as_str(), new_id.as_str()).await;
    reporter
        .step(
            "Imported on target",
            85,
            &format!(
                "new_hosting_id={}\n{grants_note}{kv_note}{}",
                new_id.as_str(),
                carry_report_text(&carry_report)
            ),
        )
        .await;

    // ---- 4. Suspend source (best-effort) ----
    reporter
        .step("Suspending source copy (best-effort)", 95, "")
        .await;
    // Best-effort, but never silently: if the suspend fails, BOTH copies
    // are live, and telling the operator "the original is now SUSPENDED"
    // sends them to repoint DNS with two sites answering for one domain.
    let suspend = crate::dispatcher::dispatch_to_node(
        &state,
        source_dispatch,
        Request::HostingSuspend {
            sel: sel.clone(),
            reason: hyperion_types::SuspendReason::Manual {
                message: Some(format!(
                    "Migrated to node {target_node} as {} — verify and delete here when ready.",
                    new_id.as_str()
                )),
            },
        },
    )
    .await;
    let suspend_failed = match suspend {
        Ok(RpcResponse::HostingSuspend) => None,
        Ok(RpcResponse::Error(e)) => Some(e.to_string()),
        Ok(_) => Some("unexpected response".to_string()),
        Err(e) => Some(e.to_string()),
    };
    let original_state = match &suspend_failed {
        None => "The original is now SUSPENDED here as a fallback.".to_string(),
        Some(e) => {
            tracing::warn!(selector = %selector_text, error = %e, "move: suspending the source failed");
            format!(
                "WARNING: suspending the original FAILED ({e}) — it is still LIVE.\n\
                 Suspend it yourself from its page before pointing DNS at the new copy."
            )
        }
    };

    tracing::info!(
        selector = %selector_text,
        target_node = %target_node,
        new_hosting_id = new_id.as_str(),
        "migration job completed"
    );

    reporter
        .step(
            &format!("Moved to {target_node} — now finish the cutover"),
            100,
            &format!(
                "Move complete. New hosting id {} on {target_node}.\n\
                 {original_state}\n\n\
                 Next steps to go live:\n\
                 1. Point this domain's DNS at {target_node}'s IP.\n\
                 2. On the target, re-issue the TLS certificate (SSL tab) — keys never travel.\n\
                 3. Once you've confirmed the moved site serves correctly, delete the\n\
                 \x20  suspended original from its Danger tab.\n",
                new_id.as_str()
            ),
        )
        .await;
    reporter.finish(true, None).await;
}

pub async fn post_migration_export(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    headers: axum::http::HeaderMap,
    Form(form): Form<MigrationExportForm>,
) -> Result<Response, AppError> {
    let sel = match require_manage_for_selector(
        &state,
        &ctx,
        &form.selector,
        Capability::HostingMigrateClone,
    )
    .await
    {
        Ok(s) => s,
        Err(r) => return Ok(r),
    };
    let sel_url = urlencoding(&form.selector);
    // The bundle is built by this server's agent and served from this
    // server's disk (/api/migration/bundle). A site on a worker is on
    // neither, and the export used to fail with a bare "not found".
    if let Ok((_, Some(node))) = find_hosting_anywhere(&state, sel.clone()).await {
        let label = crate::dispatcher::cached_nodes(&state)
            .await
            .ok()
            .and_then(|v| v.into_iter().find(|n| n.node_id == node).map(|n| n.label))
            .unwrap_or(node);
        let msg = urlencoding(&format!(
            "Export bundles can be made only for sites on the master, and this site is on \
             {label}. To move it to another server, use Move instead."
        ));
        return Ok(Redirect::to(&format!(
            "/hostings/{}?flash_error={}#migration",
            sel_url, msg
        ))
        .into_response());
    }
    let resp =
        hyperion_rpc_client::call(&state.agent_socket, Request::HostingExport { hosting: sel })
            .await?;
    match resp {
        RpcResponse::HostingExport(mut b) => {
            // Mint the signed download URL — agent has no idea what
            // master URL the operator's browser used to reach us, so
            // the web layer is the only thing that can derive it.
            let master_url = crate::handlers::derive_master_url(&state, &headers).await;
            let exp =
                hyperion_types::now_secs() + crate::handlers::migration::BUNDLE_DOWNLOAD_TTL_SECS;
            let token = hyperion_auth::bundle_sig::mint(state.csrf_key.as_ref(), &b.bundle_id, exp);
            b.download_base_url = format!("{master_url}/api/migration/bundle/{}", b.bundle_id);
            b.bundle_token = token;
            b.token_expires_at = exp;

            let tpl = MigrationExportResultTpl {
                username: &ctx.username,
                user_initial: crate::handlers::user_initial(&ctx.username),
                active: "hostings",
                css_version: crate::handlers::css_version(),
                htmx_version: crate::handlers::htmx_version(),
                selector: &form.selector,
                bundle: b,
                csrf_token: crate::handlers::session_csrf_token(&state, &ctx),
            };
            Ok(Html(tpl.render()?).into_response())
        }
        RpcResponse::Error(e) => {
            let msg = urlencoding(&format!("Migration export failed: {}", e));
            Ok(Redirect::to(&format!(
                "/hostings/{}?flash_error={}#migration",
                sel_url, msg
            ))
            .into_response())
        }
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

#[cfg(test)]
mod clone_domain_tests {
    use super::{clone_domain_from_input, clone_www_alias};

    #[test]
    fn strips_what_an_address_bar_paste_carries() {
        for raw in [
            "www.jtmotors.cz/",
            " www.jtmotors.cz ",
            "https://www.jtmotors.cz/",
            "http://www.jtmotors.cz/some/page?x=1",
            "WWW.JTMotors.cz",
            "www.jtmotors.cz:443/",
            "www.jtmotors.cz.",
            "jtmotors.cz",
        ] {
            assert_eq!(
                clone_domain_from_input(raw).as_deref(),
                Ok("jtmotors.cz"),
                "{raw}"
            );
        }
        // Only a leading `www.` that leaves a real domain is folded.
        assert_eq!(
            clone_domain_from_input("staging.jtmotors.cz").as_deref(),
            Ok("staging.jtmotors.cz")
        );
    }

    #[test]
    fn www_alias_for_a_live_domain_only() {
        let www = |raw: &str, wanted| {
            let bare = clone_domain_from_input(raw).expect("valid");
            clone_www_alias(raw, &bare, wanted)
        };
        // A main domain, typed bare or as pasted from the address bar.
        assert_eq!(www("jtmotors.cz", true).as_deref(), Some("www.jtmotors.cz"));
        assert_eq!(
            www("https://WWW.jtmotors.cz/", true).as_deref(),
            Some("www.jtmotors.cz")
        );
        // A deeper name only when typed with its www.
        assert_eq!(www("staging.jtmotors.cz", true), None);
        assert_eq!(
            www("www.shop.example.co.uk", true).as_deref(),
            Some("www.shop.example.co.uk")
        );
        // Unticked: never.
        assert_eq!(www("www.jtmotors.cz", false), None);
    }

    #[test]
    fn refuses_what_is_still_not_a_domain() {
        for raw in [
            "/",
            "https://",
            "jtmotors",
            "staging..jtmotors.cz",
            "a b.cz",
        ] {
            assert!(clone_domain_from_input(raw).is_err(), "{raw}");
        }
    }
}

#[cfg(test)]
mod bundle_id_tests {
    use super::is_bundle_id;

    #[test]
    fn accepts_only_mig_plus_26_alnum() {
        assert!(is_bundle_id("mig_0123456789abcdefghijklmnop")); // 4 + 26
        // Wrong length, prefix, traversal, path/extension chars: all out.
        assert!(!is_bundle_id("mig_0123456789abcdefghijklmno")); // 25
        assert!(!is_bundle_id("mig_0123456789abcdefghijklmnopq")); // 27
        assert!(!is_bundle_id("bun_0123456789abcdefghijklmnop"));
        assert!(!is_bundle_id(""));
        assert!(!is_bundle_id("mig_../../../../etc/passwd"));
        assert!(!is_bundle_id("mig_0123456789abcdefghijklmn.p"));
        assert!(!is_bundle_id("mig_0123456789abcdefghijklmn/p"));
    }
}
