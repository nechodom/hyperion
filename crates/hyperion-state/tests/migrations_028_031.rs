//! Cross-cutting test for the four new migrations 028..=031.
//!
//! 028 jobs                 — generic background-job ledger
//! 029 web_sessions         — per-session revocation ledger
//! 030 hosting_quotas       — disk/memory/bandwidth caps per hosting
//! 031 backup_targets       — off-site backup destinations
//!
//! Why a single integration test instead of one per migration:
//!   * the migrations don't depend on each other but they all
//!     share the same hostings + web_users + system_users FK
//!     graph; one test verifying the full graph catches the most
//!     likely regression (a future migration that breaks an FK).
//!   * keeps the per-commit overhead of "added a migration" low —
//!     we test the schema once, not four times.
//!
//! Coverage checklist (each assertion below maps to one):
//!   ☐ ALL migrations apply to a fresh DB without panic
//!   ☐ jobs row insert + read round-trips
//!   ☐ web_sessions row insert + revoke flips state
//!   ☐ hosting_quotas upsert + read round-trips
//!   ☐ backup_targets upsert + list round-trips
//!   ☐ hosting cascade-delete cleans hosting_quotas
//!     (web_sessions + jobs + backup_targets are NOT FK'd on
//!     hostings; they survive a hosting delete which is correct.)

use hyperion_state::db::open_memory;
use sqlx::SqlitePool;

async fn seed_fk_graph(p: &SqlitePool) -> (i64, String) {
    sqlx::query(
        r#"INSERT INTO system_users (id, name, uid, home_dir, shell, created_at)
           VALUES (1, 'site_h1', 1001, '/home/site_h1', '/usr/sbin/nologin', 0)"#,
    )
    .execute(p)
    .await
    .expect("seed system_user");
    sqlx::query(
        r#"INSERT INTO hostings (id, domain, system_user_id, root_dir, state, created_at, updated_at)
           VALUES ('h1', 'example.cz', 1, '/home/site_h1/example.cz', 'active', 0, 0)"#,
    )
    .execute(p)
    .await
    .expect("seed hosting");
    sqlx::query(
        r#"INSERT INTO web_users
            (id, username, email, password_hash, role, totp_required,
             locked, failed_logins, created_at, updated_at)
           VALUES (7, 'kevin', 'k@example.com', 'x', 'admin', 0,
                   0, 0, 0, 0)"#,
    )
    .execute(p)
    .await
    .expect("seed web_user");
    (7, "h1".to_string())
}

#[tokio::test]
async fn migrations_028_to_031_coexist_and_round_trip() {
    let p = open_memory().await.expect("open mem + migrate");
    let (uid, hid) = seed_fk_graph(&p).await;

    // ---- 028 jobs ----
    hyperion_state::jobs::start(
        &p,
        hyperion_state::jobs::StartReq {
            id: "job-x",
            kind: "migration",
            target: Some("example.cz"),
            payload_json: "{}",
            actor_uid: uid,
            actor_label: "kevin",
            started_at: 100,
        },
    )
    .await
    .expect("jobs::start");
    hyperion_state::jobs::progress(&p, "job-x", "step 1", 50, "hello\n", 110)
        .await
        .expect("jobs::progress");
    let job = hyperion_state::jobs::read(&p, "job-x")
        .await
        .expect("jobs::read")
        .expect("present");
    assert_eq!(job.state, "running");
    assert_eq!(job.progress_pct, 50);

    // ---- 029 web_sessions ----
    hyperion_state::web_sessions::insert(&p, "sid-x", uid, Some("1.2.3.4"), Some("test-ua"), 200)
        .await
        .expect("web_sessions::insert");
    assert!(
        hyperion_state::web_sessions::touch_if_live(&p, "sid-x", 210)
            .await
            .expect("touch")
    );
    assert!(hyperion_state::web_sessions::revoke(&p, "sid-x", uid, 220)
        .await
        .expect("revoke"));
    assert!(
        !hyperion_state::web_sessions::touch_if_live(&p, "sid-x", 230)
            .await
            .expect("touch-2"),
        "revoked session must read as dead"
    );

    // ---- 030 hosting_quotas ----
    hyperion_state::hosting_quotas::upsert(&p, &hid, 50_000, 100_000, 512, 0, 0, 300)
        .await
        .expect("quota upsert");
    let q = hyperion_state::hosting_quotas::read(&p, &hid)
        .await
        .expect("quota read");
    assert_eq!(q.disk_soft_kib, 50_000);
    assert_eq!(q.mem_limit_mib, 512);
    hyperion_state::hosting_quotas::mark_applied(&p, &hid, 310)
        .await
        .expect("mark_applied");
    let q2 = hyperion_state::hosting_quotas::read(&p, &hid)
        .await
        .expect("quota re-read");
    assert_eq!(q2.applied_at, Some(310));

    // ---- 031 backup_targets ----
    let target_id = hyperion_state::backup_targets::upsert(
        &p,
        hyperion_state::backup_targets::UpsertReq {
            id: None,
            name: "wasabi-prod",
            kind: "s3",
            endpoint: "https://s3.example.com",
            bucket: "hyperion-backups",
            region: "us-east-1",
            access_key_id: "AKIA-redacted",
            secret_key_id: Some("/etc/hyperion/secrets/backup-1.key"),
            age_recipient: Some("age1xy..."),
            retention_daily: 7,
            retention_weekly: 4,
            retention_monthly: 12,
            enabled: true,
            now: 400,
        },
    )
    .await
    .expect("backup_target upsert");
    assert!(target_id > 0);
    let targets = hyperion_state::backup_targets::list(&p)
        .await
        .expect("backup_target list");
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].bucket, "hyperion-backups");

    // ---- Cascade rules ----
    //
    // hosting_quotas FK is `ON DELETE CASCADE` → row gone with
    // the hosting. web_sessions has user_id ON DELETE CASCADE
    // (web_user delete kills sessions) but NOT hosting_id, so a
    // hosting delete leaves them alone. jobs has no hosting FK
    // either; backup_targets is independent. Verify the cascade
    // behaviour matches the schema's intent.
    sqlx::query("PRAGMA foreign_keys = ON")
        .execute(&p)
        .await
        .expect("enable fk");
    sqlx::query("DELETE FROM hostings WHERE id = ?")
        .bind(&hid)
        .execute(&p)
        .await
        .expect("delete hosting");

    let q_after = hyperion_state::hosting_quotas::read(&p, &hid)
        .await
        .expect("re-read");
    // After cascade delete, read() returns Default (no row) — its
    // hosting_id field is the one we asked for, but every other
    // field is zero. The applied_at must be None now.
    assert!(q_after.applied_at.is_none(), "quota row should be gone");
    assert_eq!(q_after.disk_soft_kib, 0, "quota policy should be wiped");

    // backup_targets survive — no FK on hostings.
    let targets_after = hyperion_state::backup_targets::list(&p)
        .await
        .expect("list-2");
    assert_eq!(
        targets_after.len(),
        1,
        "backup target must survive a hosting delete"
    );

    // Job rows survive — they're a generic ledger, no FK back to
    // hostings (the `target` column is just a string).
    let job_after = hyperion_state::jobs::read(&p, "job-x").await.expect("read");
    assert!(job_after.is_some(), "job row must survive a hosting delete");
}
