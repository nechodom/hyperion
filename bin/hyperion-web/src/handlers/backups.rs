//! S3 off-site backup targets: create/update, delete, probe. The targets
//! are listed and edited on the Backups settings page
//! (`settings::page_backups`), with the FTP target beside them, and every
//! action here returns to a card there.
//!
//! Operators add one or more S3-compatible destinations (Wasabi,
//! Backblaze B2, Minio, AWS S3). The master's agent stores the access
//! credentials (the secret in a 0600 file), an age public key for
//! client-side encryption and how many archives per site to keep; the
//! settings sync carries them to every node.

use super::settings::chrome;
use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::state::SharedState;
use axum::extract::{Path as AxPath, State};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use hyperion_rpc::codec::{Request, Response as RpcResponse};
use hyperion_state::capabilities::Capability;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct BackupTargetForm {
    /// The target being edited; empty for a new one. The form always posts
    /// the hidden field, and `serde_urlencoded` reads a present `id=` as
    /// `Some` and then fails to parse "" as a number — so a plain
    /// `Option<i64>` answered every "add a target" with a 422.
    #[serde(default, deserialize_with = "blank_as_none")]
    pub id: Option<i64>,
    pub name: String,
    #[serde(default = "default_kind")]
    pub kind: String,
    pub endpoint: String,
    pub bucket: String,
    #[serde(default = "default_region")]
    pub region: String,
    pub access_key_id: String,
    /// Optional: only sent when the operator wants to set/rotate
    /// the secret. Empty = preserve the existing on-disk path.
    #[serde(default)]
    pub secret_key: String,
    #[serde(default)]
    pub age_recipient: String,
    #[serde(default = "default_daily")]
    pub retention_daily: i64,
    #[serde(default = "default_weekly")]
    pub retention_weekly: i64,
    #[serde(default = "default_monthly")]
    pub retention_monthly: i64,
    /// The checkbox: "on" when ticked, absent when not. Absent therefore
    /// means OFF — on an edit too, where unticking it is how a target is
    /// switched off.
    #[serde(default)]
    pub enabled: Option<String>,
}

impl BackupTargetForm {
    pub fn is_enabled(&self) -> bool {
        self.enabled.as_deref() == Some("on")
    }
}

/// An optional id from a form: empty or blank is `None`, anything else must
/// be a whole number.
fn blank_as_none<'de, D>(d: D) -> Result<Option<i64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw: Option<String> = Option::deserialize(d)?;
    match raw.as_deref().map(str::trim) {
        None | Some("") => Ok(None),
        Some(s) => s.parse().map(Some).map_err(serde::de::Error::custom),
    }
}

fn default_kind() -> String {
    "s3".into()
}
fn default_region() -> String {
    "us-east-1".into()
}
fn default_daily() -> i64 {
    7
}
fn default_weekly() -> i64 {
    4
}
fn default_monthly() -> i64 {
    12
}

pub async fn post_upsert(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Form(form): Form<BackupTargetForm>,
) -> Result<Response, AppError> {
    if !ctx.can(Capability::BackupTargets) {
        return Err(AppError::Forbidden);
    }
    let secret_key = if form.secret_key.trim().is_empty() {
        None
    } else {
        Some(form.secret_key.clone())
    };
    let age_recipient = if form.age_recipient.trim().is_empty() {
        None
    } else {
        Some(form.age_recipient.clone())
    };
    let enabled = form.is_enabled();
    let name = form.name.trim().to_string();
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::BackupTargetUpsert {
            id: form.id,
            name: form.name,
            kind: form.kind,
            endpoint: form.endpoint,
            bucket: form.bucket,
            region: form.region,
            access_key_id: form.access_key_id,
            secret_key,
            age_recipient,
            retention_daily: form.retention_daily,
            // Read by nothing — the pruner is keep-newest-N via
            // retention_daily. Stored as zero so old rows converge.
            retention_weekly: 0,
            retention_monthly: 0,
            enabled,
        },
    )
    .await?;
    // Success and failure go to DIFFERENT parameters, so "not saved: …" never
    // arrives in the green banner with a tick beside it. A save comes back to
    // the table that now lists the target; a refusal to the form it came from.
    match resp {
        RpcResponse::BackupTargetUpserted { .. } => {
            // Workers' scheduled backups read the targets the settings sync
            // gives them.
            state.cluster_sync.kick();
            let has_nodes = !chrome::enrolled_nodes(&state).await.is_empty();
            Ok(chrome::back_with_flash(
                "offsite-targets",
                &target_saved_message(&name, enabled, has_nodes),
            ))
        }
        RpcResponse::Error(e) => Ok(chrome::back_with_error(
            "offsite-s3",
            &format!("The S3 target was not saved: {e}"),
        )),
        _ => Ok(chrome::back_with_error(
            "offsite-s3",
            "The S3 target was not saved: the agent gave an unexpected answer.",
        )),
    }
}

/// The flash after an S3 target is saved.
fn target_saved_message(name: &str, enabled: bool, has_nodes: bool) -> String {
    let mut msg = format!("S3 target \u{201c}{name}\u{201d} saved");
    if !enabled {
        msg.push_str(" — it is switched off, so nothing is sent to it");
    } else if has_nodes {
        msg.push_str("; the other nodes get it within a minute");
    }
    msg.push('.');
    msg
}

pub async fn post_delete(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    AxPath(id): AxPath<i64>,
) -> Result<Response, AppError> {
    if !ctx.can(Capability::BackupTargets) {
        return Err(AppError::Forbidden);
    }
    let resp =
        hyperion_rpc_client::call(&state.agent_socket, Request::BackupTargetDelete { id }).await?;
    match resp {
        RpcResponse::BackupTargetDeleted => {
            state.cluster_sync.kick();
            Ok(chrome::back_with_flash(
                "offsite-targets",
                "S3 target deleted. Backups already copied to it stay in the bucket.",
            ))
        }
        RpcResponse::Error(e) => Ok(chrome::back_with_error(
            "offsite-targets",
            &format!("The S3 target was not deleted: {e}"),
        )),
        _ => Ok(chrome::back_with_error(
            "offsite-targets",
            "The S3 target was not deleted: the agent gave an unexpected answer.",
        )),
    }
}

/// POST /settings/backups/:id/probe — does the target's endpoint answer?
/// An HTMX fragment for the Test button's row. The agent only asks the
/// bucket URL for an HTTP answer (a 403 without credentials counts): it
/// proves the address, not the keys, so the pill says "answers" and never
/// "works". Its timing is in whole seconds, so it is not shown as
/// milliseconds.
pub async fn post_probe(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    AxPath(id): AxPath<i64>,
) -> Result<Response, AppError> {
    if !ctx.can(Capability::BackupTargets) {
        return Ok(Html(
            "<span class=\"pill err\">needs the off-site targets permission</span>".to_string(),
        )
        .into_response());
    }
    let resp =
        hyperion_rpc_client::call(&state.agent_socket, Request::BackupTargetProbe { id }).await?;
    let esc = |s: &str| askama_escape::escape(s, askama_escape::Html).to_string();
    let html = match resp {
        RpcResponse::BackupTargetProbe(p) => {
            let (cls, word) = if p.ok {
                ("pill ok", "endpoint answers")
            } else {
                ("pill err", "unreachable")
            };
            format!(
                "<span class=\"{cls}\" title=\"{}\">{word}</span>",
                esc(&p.message)
            )
        }
        RpcResponse::Error(e) => format!(
            "<span class=\"pill err\">check failed: {}</span>",
            esc(&e.to_string())
        ),
        _ => "<span class=\"pill err\">unexpected response</span>".into(),
    };
    Ok(Html(html).into_response())
}

#[cfg(test)]
mod tests {
    use super::{target_saved_message, BackupTargetForm};

    /// Through axum's own Form extractor, the thing that answers a bad body
    /// with a 422.
    fn parse(body: &str) -> Result<BackupTargetForm, String> {
        use axum::extract::FromRequest;
        let req = axum::http::Request::builder()
            .method("POST")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(axum::body::Body::from(body.to_string()))
            .expect("request");
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("rt");
        rt.block_on(axum::Form::<BackupTargetForm>::from_request(req, &()))
            .map(|axum::Form(f)| f)
            .map_err(|e| e.body_text())
    }

    const NEW: &str = "name=wasabi&kind=s3&endpoint=https%3A%2F%2Fs3.example&bucket=b\
                       &region=eu&access_key_id=AK&secret_key=&age_recipient=\
                       &retention_daily=7";

    /// The add form always posts the hidden `id`, empty for a new target.
    #[test]
    fn an_empty_id_is_a_new_target() {
        let f = parse(&format!("id=&{NEW}&enabled=on")).expect("an empty id must parse");
        assert_eq!(f.id, None);
        let f = parse(&format!("id=%20&{NEW}")).expect("a blank id must parse");
        assert_eq!(f.id, None);
        let f = parse(NEW).expect("no id at all must parse");
        assert_eq!(f.id, None);
    }

    /// The edit form posts the id of the row it was filled from.
    #[test]
    fn an_edit_carries_its_id_and_junk_is_refused() {
        let f = parse(&format!("id=42&{NEW}&enabled=on")).expect("parses");
        assert_eq!(f.id, Some(42));
        let f = parse(&format!("id=+7+&{NEW}")).expect("parses");
        assert_eq!(f.id, Some(7));
        assert!(parse(&format!("id=abc&{NEW}")).is_err());
    }

    /// An unticked box is not posted at all, and that must switch the target
    /// OFF — on an edit as much as on an add.
    #[test]
    fn an_unticked_enabled_box_means_off() {
        assert!(parse(&format!("id=3&{NEW}&enabled=on"))
            .expect("parses")
            .is_enabled());
        assert!(!parse(&format!("id=3&{NEW}")).expect("parses").is_enabled());
    }

    #[test]
    fn the_saved_flash_says_what_happens_next() {
        assert_eq!(
            target_saved_message("wasabi", true, false),
            "S3 target \u{201c}wasabi\u{201d} saved."
        );
        assert!(target_saved_message("w", true, true).contains("other nodes"));
        let off = target_saved_message("w", false, true);
        assert!(off.contains("switched off"), "{off}");
        assert!(!off.contains("other nodes"), "{off}");
    }
}
