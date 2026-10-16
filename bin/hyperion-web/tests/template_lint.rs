//! Static checks over the Askama templates.
//!
//! These catch mistakes that compile and render perfectly but fail at
//! runtime, every time, for every user — the kind that only surfaces when
//! somebody actually clicks the button in production.

use std::path::{Path, PathBuf};

/// The CSRF-minting calls on one line, as `(byte offset, function name)`.
///
/// Three spellings exist: `csrf_token_for`, the shorter `csrf_token` some
/// handlers use, and `session_csrf_token`, which mints the wildcard. The last
/// CONTAINS the second, so a match is only real when the character before it
/// cannot be part of an identifier.
fn mint_calls(line: &str) -> Vec<(usize, &'static str)> {
    let mut out = Vec::new();
    for name in ["session_csrf_token", "csrf_token_for", "csrf_token"] {
        let needle = format!("{name}(");
        let mut from = 0usize;
        while let Some(rel) = line[from..].find(&needle) {
            let at = from + rel;
            // Written as a match, not `is_none_or`: that is stable since
            // 1.82 and this workspace's MSRV is 1.80.
            let boundary = match line[..at].chars().next_back() {
                Some(c) => !c.is_ascii_alphanumeric() && c != '_',
                None => true,
            };
            if boundary {
                out.push((at, name));
            }
            from = at + needle.len();
        }
    }
    out
}

/// The template field or local a mint call is assigned to, read from the text
/// to its left: `csrf_ftp_set: csrf_token_for(..)`, `let csrf_sftp = ..`, and
/// `csrf_finish: super::session_csrf_token(..)` all yield the name.
fn mint_field(head: &str) -> Option<String> {
    let mut h = head.trim_end();
    for prefix in ["super::", "self::", "crate::", "::"] {
        if let Some(x) = h.strip_suffix(prefix) {
            h = x.trim_end();
        }
    }
    let h = h.trim_end_matches([':', '=']).trim_end();
    let ident: String = h
        .chars()
        .rev()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    (!ident.is_empty()).then_some(ident)
}

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
        "/import/agent",
        "/import/agent-bin",
        "/import/select",
        "/import/selection",
        // Machine endpoints the source box's runner drives over HTTP; there is
        // no page behind them and nothing in the panel should link to one.
        "/import/upload",
        "/import/progress",
        "/import/wizard",
        "/install/update-node-status",
        // Per-row fragment the Nodes page lazy-loads into each summary.
        "/install/node-facts",
        // Per-row DNS cell the HTTPS settings page lazy-loads for each node.
        "/settings/https/preview-dns",
        // Per-card fragment the test-site form lazy-loads into each server.
        "/hostings/new/server-facts",
        "/services/install-status",
        "/settings/panel-cert-status",
        "/settings/email-preview",
        // Lazy fragment the Alerts page loads into its recipients card.
        "/settings/alerts/recipients",
        // Lazy fragment: the one-line postfix verdict in Settings → Mail's
        // Local mail server card.
        "/settings/mail/health",
        // Lazy fragment: the Mail delivery group's body on Service health.
        "/services/mail-diagnostics",
        // Retired page; a redirect to the profile's device list so old
        // bookmarks still land.
        "/settings/sessions",
        // Retired page; folded into /protection, a redirect to its bans
        // section so old bookmarks still land.
        "/bans",
        // Old address of the node-to-node import, now /import/hyperion;
        // a redirect kept for export result pages and bookmarks.
        "/hostings/import",
        // The first-run wizard: reached through the link the installer
        // prints, walked by its own step rail, and gone once finished.
        "/setup",
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
        "settings_overview.html",
        // The Settings frame: its sub-navigation is how each section page is reached.
        "settings_base.html",
        "api_keys.html",
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
        // The Import page's source switcher (one tab per source), shared by
        // every Import tab and reached from the nav's Import entry.
        "_import_header.html",
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
        // The Settings sub-navigation is built from chrome::SECTIONS, so its
        // links are `/settings/{{ s.slug }}` in the template, not literals.
        let settings_nav = SECTIONS
            .iter()
            .any(|s| stem == format!("/settings/{}", s.slug));
        let linked = settings_nav
            || all_templates.contains(&format!("href=\"{stem}\""))
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

/// No Askama template may opt out of HTML escaping.
///
/// `escape = "none"` on a card that renders a site's own PHP error output, or
/// directory names from a tenant-owned folder, turns a customer's file into
/// script in the operator's browser — and the operator is up to super_admin.
/// Three templates shipped that way.
///
/// Where a single value genuinely IS markup, use the `|safe` filter on that
/// value: it is visible at the point of use and reviewable, which a
/// derive-level opt-out covering the whole file is not.
#[test]
fn no_template_disables_escaping() {
    let mut offenders = Vec::new();
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut stack = vec![src];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("read src dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let body = std::fs::read_to_string(&path).expect("read source");
            for (i, line) in body.lines().enumerate() {
                if line.contains("escape = \"none\"") || line.contains("escape=\"none\"") {
                    offenders.push(format!(
                        "{}:{}",
                        path.file_name().expect("name").to_string_lossy(),
                        i + 1
                    ));
                }
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "template(s) opting out of HTML escaping — any tenant-controlled value they \
         render becomes script in the operator's session:\n  {}\nUse |safe on the one \
         value that is really markup instead.",
        offenders.join("\n  ")
    );
}

/// An input's `pattern` must still be a valid regular expression under the
/// `v` flag, which is how browsers compile it now.
///
/// In `v` mode a bare `-` at the edge of a character class (`[a-z0-9-]`) is a
/// syntax error. The browser does not refuse the page: it logs to the console
/// and drops the constraint, so the field quietly accepts anything and every
/// "use a–z, 0–9 and dashes" hint built on `checkValidity()` never fires. That
/// shipped on the test-site subdomain field. Escape it: `[a-z0-9\-]`.
#[test]
fn input_patterns_survive_the_v_flag() {
    let mut offenders = Vec::new();
    for entry in std::fs::read_dir(templates_dir()).expect("read templates") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("html") {
            continue;
        }
        let body = std::fs::read_to_string(&path).expect("read template");
        for (at, value) in attr_values(&body, "pattern") {
            let b = value.as_bytes();
            let bad = (0..b.len()).any(|i| {
                b[i] == b'-'
                    && ((i > 0 && b[i - 1] == b'[')
                        || (i + 1 < b.len() && b[i + 1] == b']' && (i == 0 || b[i - 1] != b'\\')))
            });
            if bad {
                offenders.push(format!(
                    "{}:{}  {value}",
                    path.file_name().expect("name").to_string_lossy(),
                    line_of(&body, at)
                ));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "pattern attribute(s) with an unescaped `-` at the edge of a character \
         class — invalid under the `v` flag, so the browser ignores the whole \
         pattern:\n  {}",
        offenders.join("\n  ")
    );
}

/// Every form's CSRF token must be minted for the path the form POSTs to.
///
/// `check_csrf` derives the form id it verifies against from
/// `parts.uri.path()` — the literal request path. `csrf_token_for(.., form_id)`
/// mints against whatever string the handler passed. When the two disagree the
/// form is dead on arrival: it renders, it submits, and it fails 100% of the
/// time with "CSRF check failed · Source: body". Nothing catches it at compile
/// time, and it looks identical to a stale-session failure in the operator's
/// browser, so the report comes back as "my session expired" rather than "this
/// button has never worked".
///
/// That shipped: the extra-FTP-login card minted ONE token for
/// `/hostings/ftp/account` and reused it on the `/reset` and `/delete` forms,
/// so both were broken from the first commit while the create form beside them
/// worked, because only its path happened to match.
///
/// A token minted for `SESSION_WIDE_FORM_ID` ("*") verifies at any path and is
/// exempt.
#[test]
fn csrf_tokens_are_minted_for_the_path_the_form_posts_to() {
    // template variable -> the form_id(s) its mint call passed.
    let mut minted: std::collections::HashMap<String, std::collections::BTreeSet<String>> =
        std::collections::HashMap::new();
    // Variables ever filled from `session_csrf_token` hold a wildcard token
    // that verifies at ANY path. The same field name (`csrf_token`) is
    // path-scoped in one template struct and session-wide in another, and
    // this lint matches on the name alone, so a name that is EVER session-wide
    // cannot be proven wrong and is left alone.
    let mut session_wide: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let handlers = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut stack = vec![handlers];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("read src dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let body = std::fs::read_to_string(&path).expect("read handler");
            // `csrf_field: csrf_token_for(&state, &ctx, "/some/path")`, with the
            // struct field name immediately before it on the same line.
            for line in body.lines() {
                for (call, name) in mint_calls(line) {
                    let Some(field) = mint_field(&line[..call]) else {
                        continue;
                    };
                    if name == "session_csrf_token" {
                        session_wide.insert(field);
                        continue;
                    }
                    // The form id is the call's last string literal.
                    let Some(form_id) = line[call..]
                        .rsplit_once('"')
                        .and_then(|(head, _)| head.rsplit('"').next())
                    else {
                        continue;
                    };
                    minted.entry(field).or_default().insert(form_id.to_string());
                }
            }
        }
    }
    assert!(
        !minted.is_empty(),
        "found no csrf_token_for calls — the lint's parser has drifted"
    );

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

        let mut rest = body.as_str();
        while let Some(start) = rest.find("<form") {
            let after = &rest[start..];
            // The token lives in the form BODY, so take the whole element.
            let end = after.find("</form>").unwrap_or(after.len());
            let form = &after[..end];
            rest = &after[end.max(1)..];

            let Some(action) = form
                .split("action=\"")
                .nth(1)
                .and_then(|s| s.split('"').next())
            else {
                continue;
            };
            // Only forms whose action is a literal path can be checked; a
            // templated action ({{ .. }}) is resolved at render time.
            if action.contains("{{") {
                continue;
            }
            let action_path = action.split('?').next().unwrap_or(action);

            // `<input type="hidden" name="_csrf" value="{{ var }}">`, or the
            // multipart form of it in the query string.
            let var = form
                .split("name=\"_csrf\"")
                .nth(1)
                .and_then(|s| s.split("value=\"").nth(1))
                .and_then(|s| s.split('"').next())
                .or_else(|| {
                    action
                        .split("_csrf={{")
                        .nth(1)
                        .and_then(|s| s.split("}}").next())
                });
            let Some(var) = var else { continue };
            let var = var
                .trim()
                .trim_start_matches("{{")
                .trim_end_matches("}}")
                .trim();
            // Filters and non-identifier expressions are out of scope.
            let var = var.split('|').next().unwrap_or(var).trim();

            if session_wide.contains(var) {
                continue;
            }
            let Some(paths) = minted.get(var) else {
                // Not minted by csrf_token_for — a nested expression, or a
                // field this parser does not recognise.
                continue;
            };
            // The same field name minted for different paths in different
            // template structs is ambiguous; this lint reports only what it
            // can prove.
            if paths.len() != 1 {
                continue;
            }
            checked += 1;
            if !paths.iter().any(|p| p == action_path || p == "*") {
                offenders.push(format!(
                    "{name}: <form action=\"{action_path}\"> uses `{var}`, minted for {paths:?}"
                ));
            }
        }
    }
    assert!(
        checked > 0,
        "no template form matched a csrf_token_for variable — the lint has drifted"
    );
    assert!(
        offenders.is_empty(),
        "these forms carry a CSRF token minted for a DIFFERENT path, so every \
         submit fails with \"CSRF check failed\":\n  {}",
        offenders.join("\n  ")
    );
}

/// The FTP login preview must stay a lookup, not a reimplementation.
///
/// The server renders every qualifier a name could get (`data-qualifiers`,
/// from `ftplogin::login_qualifiers`) and the browser picks one by length and
/// concatenates. That is the only reason the preview cannot disagree with the
/// login the server actually creates. Rewriting the script to compute the
/// shortening itself — truncating the domain, hashing the tag — puts a second
/// copy of those rules in a language no test covers, and the first thing that
/// drifts is what the operator is shown before they click Add.
#[test]
fn the_ftp_login_preview_reads_the_servers_table() {
    let body = std::fs::read_to_string(templates_dir().join("hostings_detail.html"))
        .expect("read hostings_detail.html");
    assert!(
        body.contains("data-qualifiers=\"{{ ftp_login_qualifiers|join(\"|\") }}\""),
        "the qualifier table is gone from the login input — the preview would \
         have to compute the shortening itself"
    );
    assert!(
        body.contains("input.dataset.qualifiers"),
        "the preview script no longer reads the server's qualifier table"
    );
    assert!(
        body.contains("input.dataset.domain"),
        "the preview script no longer reads the domain it compares against to \
         decide whether to say the domain was shortened"
    );
}

/// A child template must not carry markup after its last `{% endblock %}`.
///
/// Askama renders a child by filling the parent's blocks. Anything outside a
/// block is not an error and not a warning — it is silently dropped. So a
/// `<script>` appended to the end of the file compiles, the page renders, and
/// the feature is simply absent: a toggle that draws and does nothing. That
/// happened to the file manager's "show hidden files" checkbox.
#[test]
fn no_template_has_markup_after_its_last_endblock() {
    let mut offenders = Vec::new();
    let mut checked = 0usize;
    for entry in std::fs::read_dir(templates_dir()).expect("read templates dir") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("html") {
            continue;
        }
        let body = std::fs::read_to_string(&path).expect("read template");
        // Only child templates fill blocks; a base defines them.
        if !body.contains("{% extends") {
            continue;
        }
        let Some(last) = body.rfind("{% endblock %}") else {
            continue;
        };
        checked += 1;
        let trailing = body[last + "{% endblock %}".len()..].trim();
        if !trailing.is_empty() {
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            let head: String = trailing.chars().take(60).collect();
            offenders.push(format!("{name}: {head:?}"));
        }
    }
    assert!(
        checked > 0,
        "no child templates found — the lint has drifted"
    );
    assert!(
        offenders.is_empty(),
        "these templates have markup after the last endblock, which Askama \
         silently drops:\n  {}",
        offenders.join("\n  ")
    );
}

/// An item in a tab strip must either switch a panel or navigate.
///
/// The switcher binds every `.tab` in the strip, calls `preventDefault()` and
/// then activates `element.dataset.tab`. An item styled as a tab but WITHOUT
/// `data-tab` therefore does neither: the click is swallowed, nothing is
/// activated, and — because activating an unknown id used to deactivate every
/// panel — the page went blank and stayed blank. That is what the "Move /
/// copy" link did in production.
///
/// The switcher now ignores items with no `data-tab` so the browser follows
/// their href. This checks the other half: such an item must actually HAVE an
/// href to follow, and it must not be a bare fragment, which navigates
/// nowhere.
#[test]
fn every_tab_either_switches_a_panel_or_navigates() {
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

        let mut rest = body.as_str();
        while let Some(start) = rest.find("class=\"tab\"") {
            // Back up to the start of the tag, forward to its end.
            let before = &rest[..start];
            let Some(open) = before.rfind('<') else { break };
            let after = &rest[start..];
            let Some(end) = after.find('>') else { break };
            let tag = &rest[open..start + end + 1];
            rest = &after[end..];
            checked += 1;

            if tag.contains("data-tab=") {
                continue;
            }
            let href = tag
                .split("href=\"")
                .nth(1)
                .and_then(|s| s.split('"').next())
                .unwrap_or("");
            if href.is_empty() || href.starts_with('#') {
                offenders.push(format!("{name}: {tag}"));
            }
        }
    }
    assert!(checked > 0, "no tabs found — the lint has drifted");
    assert!(
        offenders.is_empty(),
        "these tab-strip items neither switch a panel (no data-tab) nor navigate \
         (no usable href), so clicking them does nothing:\n  {}",
        offenders.join("\n  ")
    );
}

const ASKAMA_COMMENTS: (&str, &str) = ("{#", "#}");
const SCRIPTS: (&str, &str) = ("<script", "</script>");

/// `body` with every span from an `open` marker through its `close` marker
/// replaced by spaces. Newlines are kept and each character becomes as many
/// spaces as it has bytes, so offsets and line numbers still match the
/// original. The earliest marker wins, so a `{#` inside a script belongs to
/// the script, and an unterminated span runs to the end.
fn blank_spans(body: &str, pairs: &[(&str, &str)]) -> String {
    let mut out = String::with_capacity(body.len());
    let mut rest = body;
    loop {
        let next = pairs
            .iter()
            .filter_map(|&(open, close)| rest.find(open).map(|at| (at, open, close)))
            .min_by_key(|&(at, _, _)| at);
        let Some((at, open, close)) = next else {
            out.push_str(rest);
            return out;
        };
        out.push_str(&rest[..at]);
        let end = rest[at + open.len()..]
            .find(close)
            .map_or(rest.len(), |e| at + open.len() + e + close.len());
        for c in rest[at..end].chars() {
            if c == '\n' {
                out.push('\n');
            } else {
                for _ in 0..c.len_utf8() {
                    out.push(' ');
                }
            }
        }
        rest = &rest[end..];
    }
}

fn line_of(text: &str, at: usize) -> usize {
    text[..at].matches('\n').count() + 1
}

/// The tag that starts at the `<` at `lt`, through its `>`.
fn tag_at(text: &str, lt: usize) -> &str {
    let end = text[lt..].find('>').map_or(text.len(), |e| lt + e + 1);
    &text[lt..end]
}

/// Every value of attribute `name` in `text`, with the attribute's offset.
/// Only a whitespace-preceded name counts, so `id` is not found inside
/// `data-id` or `node-id`.
fn attr_values<'a>(text: &'a str, name: &str) -> Vec<(usize, &'a str)> {
    let needle = format!("{name}=\"");
    let mut out = Vec::new();
    for (at, _) in text.match_indices(&needle) {
        if !text[..at].ends_with(|c: char| c.is_ascii_whitespace()) {
            continue;
        }
        let value = &text[at + needle.len()..];
        if let Some(end) = value.find('"') {
            out.push((at, &value[..end]));
        }
    }
    out
}

fn attr<'a>(tag: &'a str, name: &str) -> Option<&'a str> {
    attr_values(tag, name).first().map(|&(_, v)| v)
}

fn has_class(tag: &str, class: &str) -> bool {
    attr(tag, "class").is_some_and(|v| v.split_whitespace().any(|c| c == class))
}

// ── The Settings pages ─────────────────────────────────────────────────────
//
// Settings is an overview plus one page per section (`settings_<slug>.html`),
// each made of cards: `.item` elements whose ids are the panel's address
// space for settings. Every save redirects to `/settings/<page>#<card>`, a
// dozen other pages link into cards, and pre-upgrade `/settings#<card>`
// bookmarks are forwarded by the overview. The table of cards lives in
// `handlers::settings::chrome`; these lints hold the templates, the handlers
// and that table to each other. None of it is visible to rustc or Askama: a
// card that moved, a link to an id that is gone, or a form returning to a
// card on another page all compile, render, and drop the operator on the
// wrong place.

use hyperion_web::handlers::settings::chrome::{legacy_targets, CARDS, SECTIONS};

/// A settings page's template, with Askama comments blanked (offsets kept).
fn settings_page(slug: &str) -> (String, String) {
    let name = format!("settings_{slug}.html");
    let body = std::fs::read_to_string(templates_dir().join(&name))
        .unwrap_or_else(|e| panic!("{name}: {e} — every section in chrome::SECTIONS needs one"));
    (name, blank_spans(&body, &[ASKAMA_COMMENTS]))
}

/// Every `id="…"` in `text` that is not built at render time.
fn ids_in(text: &str) -> std::collections::BTreeSet<String> {
    attr_values(text, "id")
        .into_iter()
        .filter(|(_, v)| !v.contains('{'))
        .map(|(_, v)| v.to_string())
        .collect()
}

/// Depth of Askama blocks (`if` / `for` / `match`) open at offset `at`.
fn askama_depth_at(text: &str, at: usize) -> usize {
    let mut depth = 0usize;
    let mut rest = &text[..at];
    while let Some(i) = rest.find("{%") {
        let tag = &rest[i + 2..];
        let end = tag.find("%}").unwrap_or(tag.len());
        let word = tag[..end]
            .trim()
            .trim_start_matches('-')
            .split_whitespace()
            .next()
            .unwrap_or("");
        match word {
            "if" | "for" | "match" => depth += 1,
            "endif" | "endfor" | "endmatch" => depth = depth.saturating_sub(1),
            _ => {}
        }
        rest = &tag[end.min(tag.len())..];
    }
    depth
}

/// Which template a `/path` (no query, no fragment) renders, for links that
/// leave Settings: the overview's bookmark map points at a few.
fn template_for_path(path: &str) -> Option<String> {
    if let Some(slug) = path.strip_prefix("/settings/") {
        return SECTIONS
            .iter()
            .any(|s| s.slug == slug)
            .then(|| format!("settings_{slug}.html"));
    }
    match path {
        "/settings" => Some("settings_overview.html".into()),
        "/services" => Some("services_health.html".into()),
        "/install/node-settings" => Some("node_settings.html".into()),
        "/admin/api-keys" => Some("api_keys.html".into()),
        _ => None,
    }
}

/// Files and fragments served under /settings/ that are not section pages.
const SETTINGS_NON_PAGES: &[&str] = &[
    // The save endpoint, the retired sessions page (a redirect), and the
    // bare "/settings/" prefix some cache code matches on.
    "",
    "config",
    "sessions",
    "letters.toml",
    "email-preview",
    "email-logo.img",
    "panel-cert-status",
    "alerts/recipients",
];

/// Every section has its template (extending the shared frame) and its route.
#[test]
fn every_settings_section_has_a_page_and_a_route() {
    let router = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs"))
        .expect("read lib.rs");
    let mut offenders = Vec::new();
    for s in SECTIONS {
        let (name, text) = settings_page(s.slug);
        if !text.contains("{% extends \"settings_base.html\" %}") {
            offenders.push(format!("{name} does not extend settings_base.html"));
        }
        if !router.contains(&format!("\"/settings/{}\"", s.slug)) {
            offenders.push(format!("no route for /settings/{}", s.slug));
        }
    }
    assert!(offenders.is_empty(), "{}", offenders.join("\n"));
}

/// Every card in `chrome::CARDS` is an `.item` on the page the table says,
/// rendered unconditionally — a card inside `{% if %}` is a deep link that
/// lands on nothing whenever the condition is false (a save redirect
/// included), which is why conditions go INSIDE the card.
#[test]
fn every_settings_card_is_an_unconditional_item_on_its_page() {
    let mut offenders = Vec::new();
    for (card, slug) in CARDS {
        let (name, text) = settings_page(slug);
        let needle = format!("id=\"{card}\"");
        let hits: Vec<usize> = text
            .match_indices(&needle)
            .map(|(at, _)| at)
            .filter(|&at| text[..at].ends_with(|c: char| c.is_ascii_whitespace()))
            .collect();
        match hits.as_slice() {
            [] => offenders.push(format!("{name}: no element with id=\"{card}\"")),
            [at] => {
                let lt = text[..*at].rfind('<').unwrap_or(0);
                let tag = tag_at(&text, lt);
                if !has_class(tag, "item") {
                    offenders.push(format!(
                        "{name}:{}: #{card} is not an `.item` (the save flash moves into it)",
                        line_of(&text, *at)
                    ));
                }
                let depth = askama_depth_at(&text, *at);
                if depth > 0 {
                    offenders.push(format!(
                        "{name}:{}: #{card} sits inside {depth} Askama block(s) — render the card \
                         always and put the condition inside it",
                        line_of(&text, *at)
                    ));
                }
            }
            _ => offenders.push(format!(
                "{name}: id=\"{card}\" appears {} times",
                hits.len()
            )),
        }
    }
    assert!(offenders.is_empty(), "{}", offenders.join("\n"));
}

/// Every link into Settings lands on a page that exists and, with a fragment,
/// on an id that page has. Covers `href`s in every template (and bare `#x`
/// links on a settings page), `_return_tab` values (which must name a card on
/// the SAME page — the save returns there), string literals in the handlers,
/// and the overview's bookmark map. The one-page form `/settings#x` is
/// refused outright outside chrome.rs: it only works through the bookmark
/// redirect, an extra hop with a flash of the overview.
#[test]
fn every_link_into_settings_lands() {
    let mut offenders = Vec::new();
    let page_ids = |slug: &str| ids_in(&settings_page(slug).1);
    let check_url = |from: &str, url: &str, offenders: &mut Vec<String>| {
        let (before_frag, frag) = match url.split_once('#') {
            Some((b, f)) => (b, Some(f)),
            None => (url, None),
        };
        let path = before_frag.split('?').next().unwrap_or(before_frag);
        if path == "/settings" && frag.is_some() {
            offenders.push(format!(
                "{from}: {url} — link the card's page (/settings/<page>#card), not the old one-page form"
            ));
            return;
        }
        if let Some(rest) = path.strip_prefix("/settings/") {
            if SETTINGS_NON_PAGES.contains(&rest)
                || rest.starts_with("backups/")
                || rest.starts_with("letters/")
                || !rest.chars().all(|c| c.is_ascii_lowercase())
            {
                return;
            }
            if !SECTIONS.iter().any(|s| s.slug == rest) {
                offenders.push(format!("{from}: {url} — no such Settings page"));
                return;
            }
            if let Some(f) = frag.filter(|f| !f.is_empty() && !f.contains('{')) {
                if !page_ids(rest).contains(f) {
                    offenders.push(format!(
                        "{from}: {url} — settings_{rest}.html has no id=\"{f}\""
                    ));
                }
            }
        }
    };

    // Templates.
    let mut seen_external = 0usize;
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
        let text = blank_spans(
            &std::fs::read_to_string(&path).expect("read"),
            &[ASKAMA_COMMENTS],
        );
        let own_slug = name
            .strip_prefix("settings_")
            .and_then(|n| n.strip_suffix(".html"))
            .filter(|s| SECTIONS.iter().any(|x| x.slug == *s));
        for (at, url) in attr_values(&text, "href") {
            let from = format!("{name}:{}", line_of(&text, at));
            if url.starts_with("/settings") {
                if !name.starts_with("settings_") {
                    seen_external += 1;
                }
                check_url(&from, url, &mut offenders);
            } else if let (Some(slug), Some(f)) = (own_slug, url.strip_prefix('#')) {
                if !f.is_empty() && !f.contains('{') && !page_ids(slug).contains(f) {
                    offenders.push(format!("{from}: #{f} — no such id on this page"));
                }
            }
        }
        if let Some(slug) = own_slug {
            for (at, _) in text.match_indices("name=\"_return_tab\"") {
                let Some(lt) = text[..at].rfind('<') else {
                    continue;
                };
                let Some(v) = attr(tag_at(&text, lt), "value") else {
                    continue;
                };
                if v.contains('{') {
                    continue;
                }
                let lands = CARDS.iter().find(|(c, _)| *c == v).map(|(_, s)| *s);
                if lands != Some(slug) {
                    offenders.push(format!(
                        "{name}:{}: _return_tab=\"{v}\" is {} — a save must come back to a card on this page",
                        line_of(&text, at),
                        match lands {
                            Some(s) => format!("a card on /settings/{s}"),
                            None => "not a card in chrome::CARDS".into(),
                        }
                    ));
                }
            }
        }
    }
    assert!(
        seen_external > 0,
        "found no links into /settings from other pages — the scanner stopped matching"
    );

    // Literals in the handlers.
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut stack = vec![manifest.join("src")];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("read src dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs")
                || path.ends_with("settings/chrome.rs")
            {
                continue;
            }
            let body = std::fs::read_to_string(&path).expect("read source");
            let rel = path
                .strip_prefix(manifest)
                .unwrap_or(&path)
                .display()
                .to_string();
            for (i, line) in body.lines().enumerate() {
                let t = line.trim_start();
                if t.starts_with("//") {
                    continue;
                }
                for (at, _) in line.match_indices("\"/settings") {
                    let lit = &line[at + 1..];
                    let lit = &lit[..lit.find('"').unwrap_or(lit.len())];
                    check_url(&format!("{rel}:{}", i + 1), lit, &mut offenders);
                }
            }
        }
    }

    // The overview's bookmark map.
    for (id, to) in legacy_targets() {
        let (before, frag) = match to.split_once('#') {
            Some((b, f)) => (b, Some(f)),
            None => (to.as_str(), None),
        };
        let path = before.split('?').next().unwrap_or(before);
        match template_for_path(path) {
            None => offenders.push(format!("bookmark #{id} → {to}: no known page at {path}")),
            Some(tpl) => {
                if let Some(f) = frag {
                    let body = std::fs::read_to_string(templates_dir().join(&tpl))
                        .unwrap_or_else(|e| panic!("{tpl}: {e}"));
                    if !ids_in(&blank_spans(&body, &[ASKAMA_COMMENTS])).contains(f) {
                        offenders.push(format!("bookmark #{id} → {to}: {tpl} has no id=\"{f}\""));
                    }
                }
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "links into Settings that land on nothing:\n  {}",
        offenders.join("\n  ")
    );
}

/// `<div>`, `<fieldset>` and `<details>` balance on every Settings page. A
/// stray close ends a `fieldset.group` early, and with it the `disabled`
/// that keeps a non-Owner's view read-only.
#[test]
fn settings_pages_are_balanced() {
    let mut offenders = Vec::new();
    let mut pages: Vec<String> = SECTIONS
        .iter()
        .map(|s| format!("settings_{}.html", s.slug))
        .collect();
    pages.push("settings_overview.html".into());
    pages.push("settings_base.html".into());
    for name in pages {
        let body = std::fs::read_to_string(templates_dir().join(&name)).expect("read");
        let markup = blank_spans(&body, &[ASKAMA_COMMENTS, SCRIPTS]);
        for tag in ["div", "fieldset", "details", "form"] {
            let opens = markup
                .match_indices(&format!("<{tag}"))
                .filter(|(at, _)| {
                    matches!(
                        markup.as_bytes().get(at + 1 + tag.len()),
                        Some(b' ' | b'\n' | b'\t' | b'>' | b'\r')
                    )
                })
                .count();
            let closes = markup.matches(&format!("</{tag}>")).count();
            if opens != closes {
                offenders.push(format!("{name}: {opens} <{tag}> but {closes} </{tag}>"));
            }
        }
    }
    assert!(offenders.is_empty(), "{}", offenders.join("\n"));
}

/// The owner-only forms are inside a `fieldset.group` that takes the page's
/// read-only switch, so a non-Owner sees them disabled instead of being
/// refused after pressing Save. Checked for every form posting to
/// `/settings/config`, the one endpoint that writes agent.toml.
#[test]
fn settings_config_forms_follow_the_read_only_switch() {
    let mut offenders = Vec::new();
    for s in SECTIONS {
        let (name, text) = settings_page(s.slug);
        let markup = blank_spans(&text, &[SCRIPTS]);
        for (at, _) in markup.match_indices("action=\"/settings/config\"") {
            // The nearest fieldset opened before the form and not yet closed.
            let before = &markup[..at];
            let open = before.rfind("<fieldset");
            let close = before.rfind("</fieldset>");
            let inside = match (open, close) {
                (Some(o), Some(c)) => o > c,
                (Some(_), None) => true,
                _ => false,
            };
            let ok = inside && open.is_some_and(|o| tag_at(&markup, o).contains("chrome.ro()"));
            if !ok {
                offenders.push(format!(
                    "{name}:{}: a /settings/config form outside a <fieldset … {{{{ chrome.ro() }}}}>",
                    line_of(&markup, at)
                ));
            }
        }
    }
    assert!(offenders.is_empty(), "{}", offenders.join("\n"));
}

/// The add-website wizard's step panels and its stepper must list the
/// same steps.
///
/// The wizard shows one `.wizard-step` at a time; the stepper's
/// `<li data-step="N">` pills drive navigation and JS marks the matching
/// panel `.is-active`. If a panel's `data-step` has no stepper pill — or
/// a pill points at a panel that no longer exists — the operator gets a
/// step they cannot reach, or a pill that activates nothing. That is the
/// create form's analogue of the blank-tab bug this file already guards
/// against, so pin the two lists to each other.
#[test]
fn the_add_website_wizard_steps_match_its_stepper() {
    let body = std::fs::read_to_string(templates_dir().join("hostings_new.html"))
        .expect("read hostings_new.html");

    // data-step values on `<div class="wizard-step …" data-step="N">`.
    let mut panels = Vec::new();
    let mut rest = body.as_str();
    while let Some(start) = rest.find("class=\"wizard-step") {
        let after = &rest[start..];
        let tag_end = after.find('>').unwrap_or(after.len());
        let tag = &after[..tag_end];
        if let Some(ds) = tag.find("data-step=\"") {
            let v: String = tag[ds + "data-step=\"".len()..]
                .chars()
                .take_while(|c| *c != '"')
                .collect();
            if !v.is_empty() {
                panels.push(v);
            }
        }
        rest = &after[tag_end..];
    }
    panels.sort();
    panels.dedup();

    // data-step values on the stepper's `<li data-step="N">` pills.
    let mut pills = Vec::new();
    let mut rest = body.as_str();
    while let Some(start) = rest.find("<li data-step=\"") {
        let after = &rest[start + "<li data-step=\"".len()..];
        let v: String = after.chars().take_while(|c| *c != '"').collect();
        if !v.is_empty() {
            pills.push(v);
        }
        rest = after;
    }
    pills.sort();
    pills.dedup();

    assert!(
        !panels.is_empty(),
        "no .wizard-step panels found in hostings_new.html — the lint has drifted"
    );
    assert_eq!(
        panels, pills,
        "the add-website wizard's step panels {panels:?} and its stepper pills \
         {pills:?} disagree; every step must appear in both or navigation breaks"
    );
}
