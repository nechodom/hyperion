//! OpenAPI 3 contract for `/api/v1`.
//!
//! The document is DERIVED from the `#[utoipa::path]` annotations on the
//! `api_v1` handlers (so it can't silently drift from the routes) and served
//! at `/api/v1/openapi.json`. `/api/v1/docs` renders it with a tiny,
//! self-hosted viewer (inline JS/CSS only — the panel CSP forbids external
//! scripts, and `connect-src 'self'` lets it fetch the JSON same-origin).
//!
//! Both endpoints are unauthenticated: an API contract is public by design
//! and leaks nothing (no data, just shapes). Adding a new `/api/v1` endpoint
//! without listing it in [`ApiDoc`] fails the drift test in `web_e2e`.

use axum::response::{Html, IntoResponse, Response};
use axum::Json;
use utoipa::OpenApi;

/// Adds the `bearer` HTTP security scheme referenced by every path's
/// `security(("bearer" = []))`.
struct SecurityAddon;

impl utoipa::Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "bearer",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("hyp_<token>")
                    .description(Some("A Hyperion API key: `Authorization: Bearer hyp_…`"))
                    .build(),
            ),
        );
    }
}

/// The generated OpenAPI document for `/api/v1`. Every handler listed under
/// `paths(...)` contributes its `#[utoipa::path]` metadata.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "Hyperion Remote API",
        version = "v1",
        description = "Scriptable remote management for a Hyperion hosting cluster. \
                       Authenticate every request with a Bearer API key minted in \
                       Settings → API keys. Slow mutations return 202 + a job id you \
                       poll at /api/v1/jobs/{id}."
    ),
    paths(
        crate::handlers::api_v1::get_me,
        crate::handlers::api_v1::get_hostings,
        crate::handlers::api_v1::get_hosting,
        crate::handlers::api_v1::get_nodes,
        crate::handlers::api_v1::get_job,
        crate::handlers::api_v1::post_suspend,
        crate::handlers::api_v1::post_resume,
        crate::handlers::api_v1::delete_hosting,
        crate::handlers::api_v1::post_create,
        crate::handlers::api_v1::patch_limits,
        crate::handlers::api_v1::patch_php,
        crate::handlers::api_v1::patch_vhost,
        crate::handlers::api_v1::post_backup,
        crate::handlers::api_v1::get_backups,
        crate::handlers::api_v1::post_cert,
        crate::handlers::api_v1::patch_expiry,
        crate::handlers::api_v1::patch_quota,
        crate::handlers::api_v1::post_wp_install,
        crate::handlers::api_v1::post_restore,
        crate::handlers::api_v1::post_certs_renew_all,
    ),
    modifiers(&SecurityAddon),
    tags(
        (name = "identity", description = "The presented key's own identity"),
        (name = "hostings", description = "Hosting inventory + lifecycle"),
        (name = "nodes", description = "Enrolled cluster nodes"),
        (name = "jobs", description = "Background job status"),
    )
)]
pub struct ApiDoc;

/// `GET /api/v1/openapi.json` — the machine-readable contract. Unauthenticated.
pub async fn get_openapi_json() -> Response {
    Json(ApiDoc::openapi()).into_response()
}

/// `GET /api/v1/docs` — a self-hosted rendering of the spec. Unauthenticated.
pub async fn get_docs() -> Response {
    Html(DOCS_HTML).into_response()
}

/// Minimal, dependency-free viewer. Inline `<script>`/`<style>` are permitted
/// by the panel CSP (`script-src 'self' 'unsafe-inline'`); it fetches the
/// same-origin `openapi.json` (`connect-src 'self'`) and lists every
/// operation. No external network use, so it works on an air-gapped box.
const DOCS_HTML: &str = r##"<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Hyperion Remote API</title>
<style>
  :root { color-scheme: light dark; }
  body { font: 14px/1.5 ui-monospace, SFMono-Regular, Menlo, monospace; margin: 0; padding: 2rem;
         max-width: 60rem; margin-inline: auto; color: #1a1a1a; background: #fafafa; }
  @media (prefers-color-scheme: dark) { body { color: #e6e6e6; background: #141414; } }
  h1 { font-size: 1.4rem; margin: 0 0 .2rem; }
  .sub { opacity: .7; margin: 0 0 1.5rem; }
  .op { border: 1px solid #8883; border-radius: 8px; padding: .6rem .9rem; margin: .6rem 0; }
  .m { display: inline-block; min-width: 4.2rem; font-weight: 700; padding: .05rem .4rem;
       border-radius: 5px; text-align: center; font-size: .8rem; }
  .get { background: #2f6feb22; color: #2f6feb; }
  .post { background: #2da44e22; color: #2da44e; }
  .delete { background: #cf222e22; color: #cf222e; }
  .path { font-weight: 600; }
  .desc { opacity: .85; margin: .35rem 0 0; }
  .params, .resp { margin: .3rem 0 0; padding-left: 1rem; opacity: .8; font-size: .86rem; }
  code { background: #8881; padding: .05rem .3rem; border-radius: 4px; }
  a { color: inherit; }
</style></head>
<body>
  <h1>Hyperion Remote API <span style="opacity:.6">v1</span></h1>
  <p class="sub">Contract: <a href="/api/v1/openapi.json">openapi.json</a> · Bearer auth: <code>Authorization: Bearer hyp_…</code></p>
  <div id="ops">Loading…</div>
  <script>
    const METHS = ["get","post","put","patch","delete"];
    fetch("/api/v1/openapi.json").then(r => r.json()).then(spec => {
      const el = document.getElementById("ops");
      el.innerHTML = "";
      const paths = spec.paths || {};
      const keys = Object.keys(paths).sort();
      for (const p of keys) {
        for (const m of METHS) {
          const op = paths[p][m];
          if (!op) continue;
          const div = document.createElement("div");
          div.className = "op";
          const params = (op.parameters || []).map(x =>
            `<code>${x.name}</code> <span style="opacity:.6">(${x.in})</span> — ${x.description || ""}`).join("<br>");
          const resps = Object.entries(op.responses || {}).map(([c, r]) =>
            `<code>${c}</code> ${r.description || ""}`).join("<br>");
          div.innerHTML =
            `<span class="m ${m}">${m.toUpperCase()}</span> <span class="path">${p}</span>` +
            (op.description ? `<div class="desc">${op.description}</div>` : "") +
            (params ? `<div class="params"><b>params</b><br>${params}</div>` : "") +
            (resps ? `<div class="resp"><b>responses</b><br>${resps}</div>` : "");
          el.appendChild(div);
        }
      }
      if (!el.children.length) el.textContent = "No operations found.";
    }).catch(e => { document.getElementById("ops").textContent = "Failed to load spec: " + e; });
  </script>
</body></html>"##;
