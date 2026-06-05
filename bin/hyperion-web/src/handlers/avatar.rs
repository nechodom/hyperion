//! Profile picture upload + serve.
//!
//! Storage: `/var/lib/hyperion/avatars/<user_id>.<ext>` where ext
//! ∈ {png, jpg, webp}. The DB column `web_users.avatar_filename`
//! holds the basename (e.g. "42.png") so the serve endpoint
//! doesn't have to probe the filesystem for every variant.
//!
//! Endpoints:
//!   - GET  /avatar/me               → bytes of current user's avatar (404 if none)
//!   - GET  /avatar/:user_id         → bytes of any user's avatar (RBAC: any logged-in user)
//!   - POST /profile/avatar/upload   → multipart upload, max 1 MB, png/jpg/webp
//!   - POST /profile/avatar/clear    → remove the avatar

use crate::auth::AuthCtx;
use crate::error::AppError;
use crate::state::SharedState;
use axum::extract::{Multipart, Path, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use hyperion_rpc::codec::{Request, Response as RpcResponse};

pub const AVATAR_ROOT: &str = "/var/lib/hyperion/avatars";
pub const MAX_AVATAR_BYTES: usize = 1024 * 1024; // 1 MB

fn mime_for(name: &str) -> &'static str {
    let lower = name.to_ascii_lowercase();
    if lower.ends_with(".png") {
        "image/png"
    } else if lower.ends_with(".jpg") || lower.ends_with(".jpeg") {
        "image/jpeg"
    } else if lower.ends_with(".webp") {
        "image/webp"
    } else if lower.ends_with(".gif") {
        "image/gif"
    } else {
        "application/octet-stream"
    }
}

/// Probe the bytes' magic to decide the ext + reject non-images.
/// Wider than the upload form's accept= attribute so we don't trust
/// the client-supplied filename / Content-Type alone.
fn detect_ext(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(&[0x89, b'P', b'N', b'G']) {
        Some("png")
    } else if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        Some("jpg")
    } else if bytes.len() >= 12 && &bytes[0..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        Some("webp")
    } else {
        None
    }
}

pub async fn get_my_avatar(
    State(state): State<SharedState>,
    ctx: AuthCtx,
) -> Result<Response, AppError> {
    let Some(sess) = ctx.session.as_ref() else {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    };
    serve_avatar(&state, sess.user_id).await
}

pub async fn get_user_avatar(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    Path(user_id): Path<i64>,
) -> Result<Response, AppError> {
    if !ctx.is_authenticated() {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    }
    serve_avatar(&state, user_id).await
}

async fn serve_avatar(state: &SharedState, user_id: i64) -> Result<Response, AppError> {
    // RPC to the agent for the filename column. Avatars themselves
    // live on the master web's filesystem (one upload point); the
    // agent only knows the basename.
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::AvatarFilename { user_id },
    )
    .await?;
    let filename = match resp {
        RpcResponse::AvatarFilename(f) => f,
        _ => return Ok(StatusCode::NOT_FOUND.into_response()),
    };
    let Some(filename) = filename else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };
    // Defense in depth — the filename came from our own DB but we
    // still refuse anything with a path separator.
    if filename.contains('/') || filename.contains('\\') || filename.contains("..") {
        return Ok(StatusCode::NOT_FOUND.into_response());
    }
    let path = std::path::PathBuf::from(AVATAR_ROOT).join(&filename);
    let bytes = match tokio::fs::read(&path).await {
        Ok(b) => b,
        Err(_) => return Ok(StatusCode::NOT_FOUND.into_response()),
    };
    let mime = mime_for(&filename);
    Ok((
        [
            (header::CONTENT_TYPE, mime.to_string()),
            // Cache for an hour — most pages render the avatar
            // multiple times. Operator can hard-refresh after upload.
            (header::CACHE_CONTROL, "private, max-age=3600".to_string()),
        ],
        bytes,
    )
        .into_response())
}

pub async fn post_avatar_upload(
    State(state): State<SharedState>,
    ctx: AuthCtx,
    mut mp: Multipart,
) -> Result<Response, AppError> {
    let Some(sess) = ctx.session.as_ref() else {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    };
    let user_id = sess.user_id;
    let mut bytes: Vec<u8> = Vec::new();
    while let Some(field) = mp
        .next_field()
        .await
        .map_err(|e| AppError::BadRequest(format!("multipart: {e}")))?
    {
        if field.name().unwrap_or("") == "file" {
            bytes = field
                .bytes()
                .await
                .map_err(|e| AppError::BadRequest(format!("file: {e}")))?
                .to_vec();
            break;
        }
    }
    if bytes.is_empty() {
        return Ok(Redirect::to("/profile?flash_error=No+file+uploaded").into_response());
    }
    if bytes.len() > MAX_AVATAR_BYTES {
        return Ok(Redirect::to(&format!(
            "/profile?flash_error=Avatar+too+large+%28max+{}KB%29",
            MAX_AVATAR_BYTES / 1024
        ))
        .into_response());
    }
    let Some(ext) = detect_ext(&bytes) else {
        return Ok(Redirect::to(
            "/profile?flash_error=Unsupported+image+format+%28png%2Fjpg%2Fwebp+only%29",
        )
        .into_response());
    };
    let filename = format!("{}.{}", user_id, ext);

    // Ensure dir exists.
    if let Err(e) = tokio::fs::create_dir_all(AVATAR_ROOT).await {
        return Err(AppError::Internal(format!("mkdir avatars: {e}")));
    }
    let path = std::path::PathBuf::from(AVATAR_ROOT).join(&filename);
    // Drop any pre-existing avatar with a different ext (operator
    // switching from .png to .jpg) so we don't leak storage.
    for old_ext in &["png", "jpg", "webp", "gif"] {
        if *old_ext == ext {
            continue;
        }
        let old = std::path::PathBuf::from(AVATAR_ROOT).join(format!("{user_id}.{old_ext}"));
        let _ = tokio::fs::remove_file(&old).await;
    }
    if let Err(e) = tokio::fs::write(&path, &bytes).await {
        return Err(AppError::Internal(format!("write avatar: {e}")));
    }
    let resp = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::AvatarSet {
            user_id,
            filename: Some(filename),
        },
    )
    .await?;
    match resp {
        RpcResponse::AvatarSet => Ok(Redirect::to("/profile?flash=Avatar+updated").into_response()),
        RpcResponse::Error(e) => Ok(Redirect::to(&format!(
            "/profile?flash_error=Avatar+save+failed%3A+{}",
            urlencode(&e.to_string())
        ))
        .into_response()),
        _ => Err(AppError::Internal("unexpected response".into())),
    }
}

pub async fn post_avatar_clear(
    State(state): State<SharedState>,
    ctx: AuthCtx,
) -> Result<Response, AppError> {
    let Some(sess) = ctx.session.as_ref() else {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    };
    let user_id = sess.user_id;
    for ext in &["png", "jpg", "webp", "gif"] {
        let p = std::path::PathBuf::from(AVATAR_ROOT).join(format!("{user_id}.{ext}"));
        let _ = tokio::fs::remove_file(&p).await;
    }
    let _ = hyperion_rpc_client::call(
        &state.agent_socket,
        Request::AvatarSet {
            user_id,
            filename: None,
        },
    )
    .await;
    Ok(Redirect::to("/profile?flash=Avatar+removed").into_response())
}

fn urlencode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}
