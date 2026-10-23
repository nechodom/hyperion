//! Tests for `service::auth`.

use super::*;

/// A deleted account must not keep acting through a cookie that is still
/// validly signed.
#[tokio::test]
async fn a_deleted_user_has_no_standing() {
    let pool = open_memory().await.expect("open");
    let s = svc(pool.clone(), happy_mocks());
    let st = s.web_session_touch("sid", 999_999).await.expect("touch");
    assert!(!st.known_user, "an unknown user id must not be known");
    assert_eq!(st.caps, 0, "and carries no capabilities of its own");
    // NOT reported as locked: there is no row to say so. The web layer
    // distinguishes a deleted account from the bootstrap admin, whose
    // record lives in a file rather than in this table.
    assert!(!st.locked);
}
