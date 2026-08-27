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
