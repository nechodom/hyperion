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
