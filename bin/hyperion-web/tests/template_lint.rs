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
        "/import/ssh",
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
        "/services/install-status",
        "/settings/panel-cert-status",
        "/settings/email-preview",
        // Retired page; a redirect to the profile's device list so old
        // bookmarks still land.
        "/settings/sessions",
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

// ── The settings page ──────────────────────────────────────────────────────
//
// Settings is ONE template: a tab strip, ten tab panels switched by a script at
// the bottom of settings.html, and a page that a dozen other templates and
// handlers link into by fragment. Nothing below is visible to rustc or to
// Askama, which never parses the HTML: a panel that loses its tab, one missing
// `</div>`, or a link to a card that moved to another tab all compile, render,
// and show the operator a blank or wrong tab.

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

/// Every `<div …>` open (`true`) and `</div>` close (`false`) in `text`, as
/// `(byte offset, is_open)` in document order.
fn div_tags(text: &str) -> Vec<(usize, bool)> {
    let name_ends = |at: usize| {
        matches!(
            text.as_bytes().get(at),
            Some(b' ' | b'\t' | b'\r' | b'\n' | b'>' | b'/')
        )
    };
    let mut out: Vec<(usize, bool)> = text
        .match_indices("<div")
        .filter(|&(at, _)| name_ends(at + "<div".len()))
        .map(|(at, _)| (at, true))
        .chain(
            text.match_indices("</div")
                .filter(|&(at, _)| name_ends(at + "</div".len()))
                .map(|(at, _)| (at, false)),
        )
        .collect();
    out.sort_unstable();
    out
}

/// One `.tab-panel` element of settings.html.
struct TabPanel {
    /// Its `id`: `tab-` plus its tab's `data-tab` when it is wired up right.
    id: Option<String>,
    /// Offset of its opening `<div`.
    open: usize,
    /// Offset of the `</div>` that closes it, when the divs balance that far.
    close: Option<usize>,
    /// Divs already open when it starts; 1 = directly inside `.tab-panels`.
    depth: usize,
    /// Index of the panel it has ended up nested inside, if any.
    inside: Option<usize>,
}

/// settings.html as its tab switcher sees it.
struct SettingsPage {
    /// The template with only its Askama comments blanked.
    source: String,
    /// The template with Askama comments AND `<script>` elements blanked:
    /// the markup a browser builds elements from.
    markup: String,
    /// `data-tab` values in the tab strip, with their offsets.
    tabs: Vec<(usize, String)>,
    /// From the `.tab-panels` wrapper's `<div` to its `/tab-panels` comment.
    region: std::ops::Range<usize>,
    /// Every `.tab-panel` inside the region, in document order.
    panels: Vec<TabPanel>,
    /// `.tab-panel` elements outside the region.
    stray_panels: Vec<usize>,
    /// `<div` opens and `</div>` closes inside the region.
    opens: usize,
    closes: usize,
    /// The `</div>` that closes the `.tab-panels` wrapper itself.
    wrapper_close: Option<usize>,
    /// `</div>`s in the region with nothing left open to close.
    unmatched_closes: Vec<usize>,
    /// `<div`s in the region still open when it ends.
    unclosed_opens: Vec<usize>,
}

fn read_settings_page() -> SettingsPage {
    let body =
        std::fs::read_to_string(templates_dir().join("settings.html")).expect("read settings.html");
    let source = blank_spans(&body, &[ASKAMA_COMMENTS]);
    let markup = blank_spans(&body, &[ASKAMA_COMMENTS, SCRIPTS]);

    // The switcher binds `.tabs .tab`, so the strip is the `.tabs` element.
    let class_at = |class: &str| {
        attr_values(&markup, "class")
            .into_iter()
            .find(|(_, v)| v.split_whitespace().any(|c| c == class))
            .and_then(|(at, _)| markup[..at].rfind('<'))
    };
    let strip = class_at("tabs")
        .expect("settings.html has no `.tabs` strip — the settings lints have drifted");
    let strip_tag: String = markup[strip + 1..]
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric())
        .collect();
    let strip_end = markup[strip..]
        .find(&format!("</{strip_tag}>"))
        .map_or(markup.len(), |e| strip + e);
    let tabs = attr_values(&markup[strip..strip_end], "data-tab")
        .into_iter()
        .map(|(at, v)| (strip + at, v.to_string()))
        .collect();

    let start = class_at("tab-panels").expect(
        "settings.html has no `<div class=\"tab-panels\">` — the settings lints have drifted",
    );
    let end = body[start..].find("/tab-panels").map(|e| start + e).expect(
        "settings.html has no `{# /tab-panels #}` comment after the `.tab-panels` \
         wrapper — the settings lints have drifted",
    );

    let mut panels: Vec<TabPanel> = Vec::new();
    // One entry per open div: its offset, and its index in `panels` if it is one.
    let mut open_stack: Vec<(usize, Option<usize>)> = Vec::new();
    let mut unmatched_closes = Vec::new();
    let mut wrapper_close = None;
    let (mut opens, mut closes) = (0usize, 0usize);
    for (rel, is_open) in div_tags(&markup[start..end]) {
        let at = start + rel;
        if is_open {
            opens += 1;
            let tag = tag_at(&markup, at);
            let mut panel = None;
            if has_class(tag, "tab-panel") {
                panels.push(TabPanel {
                    id: attr(tag, "id").map(str::to_string),
                    open: at,
                    close: None,
                    depth: open_stack.len(),
                    inside: open_stack.iter().rev().find_map(|&(_, p)| p),
                });
                panel = Some(panels.len() - 1);
            }
            open_stack.push((at, panel));
        } else {
            closes += 1;
            match open_stack.pop() {
                Some((_, Some(i))) => panels[i].close = Some(at),
                Some((opened, None)) if opened == start => wrapper_close = Some(at),
                Some((_, None)) => {}
                None => unmatched_closes.push(at),
            }
        }
    }
    let unclosed_opens = open_stack.into_iter().map(|(at, _)| at).collect();
    let stray_panels = div_tags(&markup)
        .into_iter()
        .filter(|&(at, is_open)| {
            is_open && !(start..end).contains(&at) && has_class(tag_at(&markup, at), "tab-panel")
        })
        .map(|(at, _)| at)
        .collect();

    SettingsPage {
        source,
        markup,
        tabs,
        region: start..end,
        panels,
        stray_panels,
        opens,
        closes,
        wrapper_close,
        unmatched_closes,
        unclosed_opens,
    }
}

/// Every tab in the settings strip must have exactly one panel, and every
/// panel a tab.
///
/// The switcher toggles `.active` on the strip item whose `data-tab` is X and
/// on the panel whose id is `tab-X`. A tab with no panel therefore blanks the
/// page when clicked. A panel with no tab can never be opened, by a click or
/// by any deep link into one of its cards, so every card on it is lost. Two
/// panels with one id both show at once. All three are one typo away when
/// cards and whole tabs move, and none of them is an error anywhere.
#[test]
fn settings_tabs_and_panels_match() {
    let page = read_settings_page();
    let line = |at: usize| line_of(&page.markup, at);
    let mut offenders = Vec::new();
    assert!(
        !page.tabs.is_empty(),
        "no data-tab in the settings tab strip — the lint has drifted"
    );
    assert!(
        !page.panels.is_empty(),
        "no .tab-panel inside .tab-panels on the settings page — the lint has drifted"
    );

    let mut strip = std::collections::BTreeSet::new();
    for (at, tab) in &page.tabs {
        if !strip.insert(tab.as_str()) {
            offenders.push(format!(
                "settings.html:{}: data-tab=\"{tab}\" is in the strip twice",
                line(*at)
            ));
        }
    }
    // The switcher's last resort is `activate('general')`: with no such tab, a
    // URL naming nothing it knows opens onto an empty page.
    if !strip.contains("general") {
        offenders
            .push("settings.html: no `general` tab, which the switcher falls back to".to_string());
    }

    for p in &page.panels {
        match p.id.as_deref().and_then(|id| id.strip_prefix("tab-")) {
            None => offenders.push(format!(
                "settings.html:{}: .tab-panel with id {:?} — it must be `tab-<data-tab>`",
                line(p.open),
                p.id
            )),
            Some(tab) if !strip.contains(tab) => offenders.push(format!(
                "settings.html:{}: panel `tab-{tab}` has no data-tab=\"{tab}\" in the strip, \
                 so nothing can open it",
                line(p.open)
            )),
            Some(_) => {}
        }
    }
    for at in &page.stray_panels {
        offenders.push(format!(
            "settings.html:{}: .tab-panel outside `<div class=\"tab-panels\">`; the switcher \
             only toggles `.tab-panels .tab-panel`",
            line(*at)
        ));
    }

    let ids = attr_values(&page.markup, "id");
    for tab in &strip {
        let want = format!("tab-{tab}");
        let panels = page
            .panels
            .iter()
            .filter(|p| p.id.as_deref() == Some(want.as_str()))
            .count();
        let elements = ids.iter().filter(|(_, id)| *id == want).count();
        if panels != 1 || elements != 1 {
            offenders.push(format!(
                "settings.html: tab `{tab}` has {panels} .tab-panel with id=\"{want}\" and \
                 {elements} element(s) with that id in all; it needs exactly one of each"
            ));
        }
    }

    assert!(
        offenders.is_empty(),
        "the settings tab strip and its panels disagree — a tab opens a blank page or \
         a panel can never be opened:\n  {}",
        offenders.join("\n  ")
    );
}

/// Between `<div class="tab-panels">` and its `{# /tab-panels #}` comment,
/// every `<div>` must be closed, and every panel must sit directly inside the
/// wrapper.
///
/// Only the active panel is shown. One missing `</div>` nests the NEXT panel
/// inside the current one, so that tab opens onto a blank page whenever the
/// tab above it is not the active one. One extra `</div>` closes `.tab-panels`
/// early, and every panel after it drops out of `.tab-panels .tab-panel`,
/// which is what the switcher toggles. Moving cards between tabs is cutting
/// and pasting runs of divs, which is exactly how both happen.
///
/// Askama comments and `<script>` elements are ignored: markup in either is
/// never parsed as markup by the browser.
#[test]
fn settings_panels_div_balanced() {
    let page = read_settings_page();
    let line = |at: usize| line_of(&page.markup, at);
    let mut offenders = Vec::new();
    assert!(
        !page.panels.is_empty(),
        "no .tab-panel inside .tab-panels on the settings page — the lint has drifted"
    );

    // Only the last `</div>` before the comment may close the wrapper.
    if let Some(at) = page.wrapper_close {
        if !page.unmatched_closes.is_empty() || page.panels.iter().any(|p| p.open > at) {
            offenders.push(format!(
                "settings.html:{}: this </div> closes `.tab-panels` early — one </div> too \
                 many in the panel above it",
                line(at)
            ));
        }
    }
    for at in &page.unmatched_closes {
        offenders.push(format!(
            "settings.html:{}: </div> with nothing left open — `.tab-panels` is already closed",
            line(*at)
        ));
    }
    for at in &page.unclosed_opens {
        offenders.push(format!(
            "settings.html:{}: <div> still open at the /tab-panels comment",
            line(*at)
        ));
    }
    for p in &page.panels {
        let name = p.id.as_deref().unwrap_or("(no id)");
        if p.depth == 0 {
            offenders.push(format!(
                "settings.html:{}: panel {name} starts after `.tab-panels` was closed by an \
                 extra </div>",
                line(p.open)
            ));
        } else if p.depth > 1 {
            let unclosed = p.depth - 1;
            offenders.push(match p.inside {
                Some(i) => {
                    let around = page.panels[i].id.as_deref().unwrap_or("(no id)");
                    format!(
                        "settings.html:{}: panel {name} is nested inside panel {around} \
                         ({unclosed} unclosed <div> above it), so it only shows while \
                         {around} is active",
                        line(p.open)
                    )
                }
                None => format!(
                    "settings.html:{}: panel {name} is not directly inside .tab-panels \
                     ({unclosed} unclosed <div> between the panels above it)",
                    line(p.open)
                ),
            });
        }
    }

    assert!(
        page.opens == page.closes && offenders.is_empty(),
        "settings.html has {} <div> and {} </div> between <div class=\"tab-panels\"> and \
         {{# /tab-panels #}} (comments and scripts ignored):\n  {}",
        page.opens,
        page.closes,
        offenders.join("\n  ")
    );
}

/// The value `alias` is mapped to in `js` — by an object literal
/// (`system: 'updates'`, `'system': "updates"`) or a pair list
/// (`['system', 'updates']`) — if anything maps it.
fn js_alias_target<'a>(js: &'a str, alias: &str) -> Option<&'a str> {
    for (at, _) in js.match_indices(alias) {
        let before = js[..at].chars().next_back();
        if before.is_some_and(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')) {
            continue;
        }
        let rest = js[at + alias.len()..]
            .trim_start_matches(['\'', '"'])
            .trim_start();
        let Some(rest) = rest.strip_prefix([':', ',']) else {
            continue;
        };
        let rest = rest.trim_start();
        let Some(quote) = rest.chars().next().filter(|&c| c == '\'' || c == '"') else {
            continue;
        };
        let value = &rest[1..];
        if let Some(end) = value.find(quote) {
            return Some(&value[..end]);
        }
    }
    None
}

/// The fragment of a URL into the settings page (`/settings#X`,
/// `/settings?…#X`), or None for another page such as `/settings/backups`,
/// for no fragment, and for a fragment only known at render time.
fn settings_fragment(url: &str) -> Option<&str> {
    let tail = url.strip_prefix("/settings")?;
    if !(tail.is_empty() || tail.starts_with(['#', '?', '{'])) {
        return None;
    }
    let (_, frag) = tail.split_once('#')?;
    (!frag.is_empty() && !frag.contains('{')).then_some(frag)
}

/// The string literals the arms of `fn name`'s `match` evaluate to (`"acme"`
/// from `"acme" => "acme",` or `"trash" => Some("trash"),`), or None when
/// the function is not in `src`.
fn match_arm_values(src: &str, name: &str) -> Option<Vec<String>> {
    let start = src.find(&format!("fn {name}("))?;
    let body = &src[start..];
    let body = &body[..body.find("\n}").unwrap_or(body.len())];
    Some(
        body.lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .filter_map(|l| {
                let (_, rhs) = l.split_once("=>")?;
                let rhs = rhs.trim_start();
                let lit = rhs.strip_prefix("Some(").unwrap_or(rhs).strip_prefix('"')?;
                Some(lit[..lit.find('"')?].to_string())
            })
            .collect(),
    )
}

/// Every link into the settings page must land on something.
///
/// `/settings#X` opens the tab whose `data-tab` is X, or the tab holding the
/// element whose id is X — but only an element INSIDE a `.tab-panel`, because
/// the switcher climbs to the panel to learn which tab to open. Anything else
/// does nothing: the page opens on whatever tab was last used, and the
/// operator sent to "Settings → Trash" has to go looking for it. Deep links
/// come from four places, all checked here: `href`s in every template (and
/// the bare `#X` links on the settings page itself), the `_return_tab` a
/// settings form sends back, the redirect URLs the handlers write, and the
/// `section_to_tab` / `sanitize_return_tab` tables every config save
/// redirects through.
///
/// The retired tab ids (`system`, `testnodes`, `retention`) stay valid for
/// as long as the page's LEGACY alias map rewrites them to the cards that
/// replaced them. The map is read from the page's own script, so an alias
/// that points nowhere, or one that shadows a live id, is reported too.
#[test]
fn settings_deep_links_resolve() {
    const RETIRED: &[&str] = &["system", "testnodes", "retention"];
    let page = read_settings_page();
    let mut offenders = Vec::new();

    // What a fragment can name: a tab, or an id inside a panel.
    let mut targets: std::collections::BTreeSet<&str> =
        page.tabs.iter().map(|(_, t)| t.as_str()).collect();
    for p in &page.panels {
        let end = p.close.unwrap_or(page.region.end);
        for (_, id) in attr_values(&page.markup[p.open..end], "id") {
            if !id.contains('{') {
                targets.insert(id);
            }
        }
    }

    // resolve() rewrites a retired id before it looks anything up.
    let mut scripts = String::new();
    let mut rest = page.source.as_str();
    while let Some(at) = rest.find("<script") {
        let script = &rest[at..];
        let end = script.find("</script>").unwrap_or(script.len());
        scripts.push_str(&script[..end]);
        scripts.push('\n');
        rest = &script[end..];
    }
    let legacy: std::collections::BTreeMap<&str, &str> = RETIRED
        .iter()
        .filter_map(|&alias| js_alias_target(&scripts, alias).map(|to| (alias, to)))
        .collect();
    for (&alias, &to) in &legacy {
        if targets.contains(alias) {
            offenders.push(format!(
                "settings.html: `{alias}` is both a retired id in the LEGACY alias map and a \
                 live tab or id; the map rewrites it first, so the live one is unreachable"
            ));
        }
        if !targets.contains(to) {
            offenders.push(format!(
                "settings.html: the LEGACY alias map sends #{alias} to #{to}, which is neither \
                 a tab nor an id inside a panel"
            ));
        }
    }

    // (where, fragment)
    let mut links: Vec<(String, String)> = Vec::new();
    let mut from_other_pages = 0usize;
    for entry in std::fs::read_dir(templates_dir()).expect("read templates dir") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("html") {
            continue;
        }
        let body = std::fs::read_to_string(&path).expect("read template");
        let text = blank_spans(&body, &[ASKAMA_COMMENTS]);
        let name = path
            .file_name()
            .expect("file name")
            .to_string_lossy()
            .into_owned();
        let mut hrefs = vec!["href=\"/settings"];
        if name == "settings.html" {
            // In-page links on the settings page itself go through the same resolve().
            hrefs.push("href=\"#");
        }
        for needle in hrefs {
            for (at, _) in text.match_indices(needle) {
                let url_at = at + "href=\"".len();
                let Some(len) = text[url_at..].find('"') else {
                    continue;
                };
                let url = &text[url_at..url_at + len];
                let frag = match url.strip_prefix('#') {
                    Some(f) if !f.is_empty() && !f.contains('{') => Some(f),
                    Some(_) => None,
                    None => settings_fragment(url),
                };
                if let Some(frag) = frag {
                    if name != "settings.html" {
                        from_other_pages += 1;
                    }
                    links.push((format!("{name}:{}", line_of(&text, at)), frag.to_string()));
                }
            }
        }
        if name == "settings.html" {
            // A form's `_return_tab` becomes the fragment of the redirect after it saves.
            for (at, _) in text.match_indices("name=\"_return_tab\"") {
                let Some(lt) = text[..at].rfind('<') else {
                    continue;
                };
                if let Some(value) = attr(tag_at(&text, lt), "value") {
                    if !value.contains('{') {
                        links.push((
                            format!("settings.html:{} (_return_tab)", line_of(&text, at)),
                            value.to_string(),
                        ));
                    }
                }
            }
        }
    }

    // Redirects written as literals anywhere in the handlers.
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut stack = vec![manifest.join("src")];
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
            let rel = path
                .strip_prefix(manifest)
                .unwrap_or(&path)
                .display()
                .to_string();
            for (i, line) in body.lines().enumerate() {
                if line.trim_start().starts_with("//") {
                    continue;
                }
                for (at, _) in line.match_indices("\"/settings") {
                    let lit = &line[at + 1..];
                    let lit = &lit[..lit.find('"').unwrap_or(lit.len())];
                    if let Some(frag) = settings_fragment(lit) {
                        links.push((format!("{rel}:{}", i + 1), frag.to_string()));
                    }
                }
            }
        }
    }

    // Every config save redirects to `#{tab}`, where tab comes from these two.
    let settings_rs = std::fs::read_to_string(manifest.join("src/handlers/settings.rs"))
        .expect("read src/handlers/settings.rs");
    for f in ["section_to_tab", "sanitize_return_tab"] {
        let values = match_arm_values(&settings_rs, f).unwrap_or_else(|| {
            panic!(
                "fn {f} is gone from src/handlers/settings.rs — config saves redirect \
                 through it, so this lint has to follow it"
            )
        });
        assert!(
            !values.is_empty(),
            "read no anchors out of fn {f} in settings.rs — the lint has drifted"
        );
        links.extend(
            values
                .into_iter()
                .map(|v| (format!("settings.rs {f}()"), v)),
        );
    }

    assert!(
        from_other_pages > 0,
        "found no links into /settings from other pages — the scanner stopped matching"
    );
    for (from, frag) in &links {
        let lands = legacy.get(frag.as_str()).copied().unwrap_or(frag.as_str());
        if !targets.contains(lands) {
            let hint = if RETIRED.contains(&frag.as_str()) && !legacy.contains_key(frag.as_str()) {
                " (a retired tab id, and the page's LEGACY alias map no longer rewrites it)"
            } else {
                ""
            };
            offenders.push(format!("{from} → #{frag}{hint}"));
        }
    }

    assert!(
        offenders.is_empty(),
        "links into /settings that land on nothing — no tab has that data-tab and no \
         element inside a tab panel has that id, so the page opens on some other tab:\n  {}",
        offenders.join("\n  ")
    );
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
