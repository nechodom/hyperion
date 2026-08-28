//! Static checks over the Askama templates.
//!
//! These catch mistakes that compile and render perfectly but fail at
//! runtime, every time, for every user — the kind that only surfaces when
//! somebody actually clicks the button in production.

use std::path::{Path, PathBuf};

fn templates_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("templates")
}

/// Every `multipart/form-data` form must carry its CSRF token in the
/// action's QUERY STRING, not in a hidden field.
///
/// `check_csrf` refuses to buffer multipart bodies — an upload can be
/// gigabytes — so it looks for `?_csrf=` (or the `X-CSRF-Token` header,
/// which a plain form submit cannot set). A hidden `_csrf` input looks
/// exactly like the working pattern used by every urlencoded form in the
/// codebase, is never read, and the upload fails 100% of the time with
/// "CSRF check failed · Source: none". That shipped in the e-mail logo
/// upload and reached a user.
#[test]
fn multipart_forms_carry_csrf_in_the_query_string() {
    let mut offenders = Vec::new();
    let mut checked = 0usize;
    for entry in std::fs::read_dir(templates_dir()).expect("read templates dir") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("html") {
            continue;
        }
        let body = std::fs::read_to_string(&path).expect("read template");
        let name = path
            .file_name()
            .expect("file name")
            .to_string_lossy()
            .into_owned();

        // Walk each `<form …>` open tag and look at its attributes.
        let mut rest = body.as_str();
        while let Some(start) = rest.find("<form") {
            let after = &rest[start..];
            let Some(end) = after.find('>') else { break };
            let tag = &after[..=end];
            if tag.contains("multipart/form-data") {
                checked += 1;
                let action = tag
                    .split("action=\"")
                    .nth(1)
                    .and_then(|s| s.split('"').next())
                    .unwrap_or("");
                if !action.contains("_csrf=") {
                    offenders.push(format!("{name}: action={action:?}"));
                }
            }
            rest = &after[end..];
        }
    }
    assert!(
        checked > 0,
        "found no multipart forms at all — the scanner stopped matching, \
         so it is no longer protecting anything"
    );
    assert!(
        offenders.is_empty(),
        "multipart form(s) without `?_csrf=` in the action — these 403 on \
         every submit:\n  {}",
        offenders.join("\n  ")
    );
}

/// `data-confirm-*` must sit on the `<form>`, never on the `<button>`.
///
/// The driver in base.html listens for `submit` and reads
/// `ev.target.dataset.confirmTitle` — and a submit event's target is the
/// FORM. Attributes on the button are invisible to it, so the dialog never
/// opens and the action fires immediately. That is the exact opposite of
/// what a confirmation is for, and it is invisible in review because the
/// markup looks right.
///
/// It shipped that way on the FTP card's "Enable FTPS (required)" button —
/// an action that restarts a shared daemon and can lock out every FTP
/// client on the node.
#[test]
fn confirm_dialogs_are_declared_on_the_form() {
    let mut offenders = Vec::new();
    let mut checked = 0usize;
    for entry in std::fs::read_dir(templates_dir()).expect("read templates dir") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("html") {
            continue;
        }
        let body = std::fs::read_to_string(&path).expect("read template");
        let name = path
            .file_name()
            .expect("name")
            .to_string_lossy()
            .into_owned();

        let mut rest = body.as_str();
        let mut offset = 0usize;
        while let Some(at) = rest.find("data-confirm-title") {
            offset += at;
            // Walk back to the opening '<' of the tag this attribute is in.
            let before = &body[..offset];
            if let Some(lt) = before.rfind('<') {
                let tag: String = body[lt + 1..]
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric())
                    .collect();
                // Askama comments ({# … #}) can contain example markup.
                let in_comment = before
                    .rfind("{#")
                    .is_some_and(|c| before[c..].find("#}").is_none());
                if !in_comment && !tag.is_empty() {
                    checked += 1;
                    if tag != "form" {
                        let line = before.matches('\n').count() + 1;
                        offenders.push(format!("{name}:{line} on <{tag}>"));
                    }
                }
            }
            let step = at + "data-confirm-title".len();
            rest = &rest[step..];
            offset += "data-confirm-title".len();
        }
    }
    assert!(
        checked > 0,
        "found no confirm dialogs at all — the scanner stopped matching"
    );
    assert!(
        offenders.is_empty(),
        "data-confirm-* on a non-form element — the dialog never opens and the \
         action fires immediately:\n  {}",
        offenders.join("\n  ")
    );
}

/// Every `hx-get` / `hx-post` path in a template must be a registered route.
///
/// A lazy panel whose route does not exist answers 404, and HTMX does not
/// swap on a non-2xx — so the placeholder spinner stays on screen forever
/// and the operator sees a card that is permanently "loading". Nothing else
/// catches it: the handler still compiles, because an unrouted `pub fn` is
/// not dead code to rustc, and the template still renders.
///
/// That shipped: the file-permissions panel went out with its handler
/// written, its template mounted, and its two routes never registered.
#[test]
fn htmx_endpoints_have_routes() {
    let router = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs"))
        .expect("read lib.rs");

    // "/hostings/{{ x }}/perm-panel" → ["hostings", "*", "perm-panel"]
    // "/hostings/:selector/perm-panel" → ["hostings", "*", "perm-panel"]
    fn shape(path: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut rest = path.trim_start_matches('/');
        // Drop any query string — routes are registered without one.
        if let Some(q) = rest.find('?') {
            rest = &rest[..q];
        }
        for seg in rest.split('/') {
            if seg.is_empty() {
                continue;
            }
            if seg.starts_with(':') || seg.contains("{{") || seg.contains("{%") {
                out.push("*".to_string());
            } else {
                out.push(seg.to_string());
            }
        }
        out
    }

    let registered: Vec<Vec<String>> = router
        .match_indices(".route(")
        .filter_map(|(i, _)| {
            let after = &router[i..];
            let q1 = after.find('"')?;
            let q2 = after[q1 + 1..].find('"')?;
            Some(shape(&after[q1 + 1..q1 + 1 + q2]))
        })
        .collect();

    let mut missing = Vec::new();
    let mut checked = 0usize;
    for entry in std::fs::read_dir(templates_dir()).expect("read templates dir") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("html") {
            continue;
        }
        let body = std::fs::read_to_string(&path).expect("read template");
        let name = path
            .file_name()
            .expect("name")
            .to_string_lossy()
            .into_owned();
        for attr in ["hx-get=\"", "hx-post=\""] {
            let mut rest = body.as_str();
            while let Some(at) = rest.find(attr) {
                let after = &rest[at + attr.len()..];
                let Some(end) = after.find('"') else { break };
                let url = &after[..end];
                rest = &after[end..];
                // Only same-origin absolute paths are routes.
                if !url.starts_with('/') {
                    continue;
                }
                checked += 1;
                let want = shape(url);
                if !registered.contains(&want) {
                    missing.push(format!("{name}: {url}"));
                }
            }
        }
    }
    assert!(
        checked > 0,
        "found no hx-get/hx-post endpoints — the scanner stopped matching"
    );
    assert!(
        missing.is_empty(),
        "template requests an endpoint with no registered route — HTMX gets a \
         404 and the panel spins forever:\n  {}",
        missing.join("\n  ")
    );
}

/// Every full page must be reachable from the global nav, or from a page
/// that is.
///
/// The Users admin page had no nav entry at all: the only link to it in the
/// whole panel was a passing mention inside the role editor, which you reach
/// by editing a role. The page worked perfectly and simply could not be
/// found — the kind of regression that survives every other test, because
/// nothing about it is broken.
///
/// The allow-list below is for endpoints that are legitimately not
/// navigable: health probes, token-scoped flows, and polling endpoints. Add
/// to it deliberately; the default is that a page needs a way in.
#[test]
fn every_page_is_reachable_from_the_nav() {
    /// Reached by a token in the URL, by a redirect, or by a probe — not by
    /// clicking. Each entry is a decision, not an oversight.
    const NOT_NAVIGABLE: &[&str] = &[
        "/healthz",
        "/readyz",
        "/login",
        "/login/2fa",
        "/avatar",
        "/import/ssh",
        "/import/agent",
        "/import/agent-bin",
        "/import/select",
        "/import/selection",
        "/import/wizard",
        "/install/update-node-status",
        "/services/install-status",
        "/settings/panel-cert-status",
        "/settings/email-preview",
    ];

    let router = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs"))
        .expect("read lib.rs");

    // Only links from the global nav and from top-level pages count as a way
    // in. A link from a leaf — the role EDITOR, say — is not navigation:
    // you have to already be somewhere specific to see it, which is exactly
    // how the Users page stayed lost while technically being linked.
    const HUBS: &[&str] = &[
        "base.html",
        "dashboard.html",
        "hostings_list.html",
        // A per-site page reached straight from the hostings list is a hub
        // in its own right — its own tabs and actions are navigation.
        "hostings_detail.html",
        "profiles.html",
        "settings.html",
        "roles.html",
        "certs.html",
        "jobs_list.html",
        "profile.html",
        "services.html",
        "stats.html",
        "audit.html",
        "install.html",
        "nodes.html",
        "emails.html",
        "packages.html",
        "monitors.html",
        "firewall.html",
        "bans.html",
    ];
    let mut all_templates = String::new();
    for entry in std::fs::read_dir(templates_dir()).expect("read templates dir") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("html") {
            continue;
        }
        let name = path
            .file_name()
            .expect("name")
            .to_string_lossy()
            .into_owned();
        if HUBS.contains(&name.as_str()) {
            all_templates.push_str(&std::fs::read_to_string(&path).expect("read template"));
        }
    }

    let mut orphans = Vec::new();
    let mut checked = 0usize;
    for (i, _) in router.match_indices(".route(") {
        let after = &router[i..];
        let Some(q1) = after.find('"') else { continue };
        let Some(q2) = after[q1 + 1..].find('"') else {
            continue;
        };
        let path = &after[q1 + 1..q1 + 1 + q2];
        // Only GET routes render pages.
        let head = &after[..q1 + 1 + q2 + 40.min(after.len() - (q1 + 1 + q2))];
        if !head.contains("get(") {
            continue;
        }
        if path.starts_with("/api") || path.contains("-panel") || path.contains('.') {
            continue;
        }
        let stem = path.split("/:").next().unwrap_or(path);
        if NOT_NAVIGABLE.iter().any(|p| stem.starts_with(p)) {
            continue;
        }
        checked += 1;
        // Linked from anywhere in the templates counts: a sub-page reached
        // from its own parent list is properly navigable.
        let linked = all_templates.contains(&format!("href=\"{stem}\""))
            || all_templates.contains(&format!("href=\"{stem}?"))
            || all_templates.contains(&format!("href=\"{stem}#"))
            || all_templates.contains(&format!("href=\"{stem}/"));
        if !linked {
            orphans.push(path.to_string());
        }
    }
    assert!(
        checked > 0,
        "found no page routes — the scanner stopped matching"
    );
    assert!(
        orphans.is_empty(),
        "page route with no link anywhere in the panel — it exists and cannot \
         be found:\n  {}\nIf that is deliberate, add it to NOT_NAVIGABLE with \
         a reason.",
        orphans.join("\n  ")
    );
}
