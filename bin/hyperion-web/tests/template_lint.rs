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
