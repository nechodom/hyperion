//! `/settings/sessions` — retired. It was a second list of the same
//! sessions the profile page shows under "Signed-in devices"; the route
//! stays as a redirect so bookmarks and old links still land somewhere.

use axum::response::{IntoResponse, Redirect, Response};

pub async fn get_sessions() -> Response {
    Redirect::permanent("/profile#devices").into_response()
}
