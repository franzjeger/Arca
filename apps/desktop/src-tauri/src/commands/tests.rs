use super::*;
use crate::clipboard::{ClipboardManager, ClipboardProbe};
use tempfile::TempDir;
use vault_core::KdfAlgorithm;
use vault_store::VaultStore;

/// Cheap KDF so tests don't spend 64 MiB each (real vaults use defaults).
fn cheap_params() -> KdfParams {
    KdfParams {
        algorithm: KdfAlgorithm::Argon2id,
        m_cost_kib: 256,
        t_cost: 1,
        p_cost: 1,
        salt: vec![5u8; KdfParams::SALT_LEN],
    }
}

/// A state with an already-unlocked, cheap-KDF vault wired to a temp store
/// and an in-memory clipboard probe.
fn unlocked(dir: &TempDir) -> (Mutex<AppState>, ClipboardProbe) {
    let store = VaultStore::new(dir.path().join("v.vault"), "svc", "acct");
    let vault = Vault::create("pw", cheap_params()).unwrap();
    let (clip, probe) = ClipboardManager::memory();
    (Mutex::new(AppState::new(store, Some(vault), clip)), probe)
}

fn sample_input() -> LoginInput {
    LoginInput {
        id: None,
        title: "GitHub".into(),
        username: "frank-lia".into(),
        password: "p4ss".into(),
        url: "https://github.com".into(),
        totp_secret: Some("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into()),
        notes: "note".into(),
    }
}

#[test]
fn failed_password_restore_preserves_current_password_and_history() {
    let dir = TempDir::new().unwrap();
    let (state, _) = unlocked(&dir);
    let id = do_upsert_item(&state, sample_input()).unwrap();
    let mut changed = sample_input();
    changed.id = Some(id.clone());
    changed.password = "replacement".into();
    do_upsert_item(&state, changed).unwrap();
    let before = guard(&state)
        .unwrap()
        .vault()
        .unwrap()
        .get_item(parse_id(&id).unwrap())
        .unwrap();
    let blocked = dir.path().join("blocked");
    std::fs::write(&blocked, b"not a directory").unwrap();
    guard(&state).unwrap().store = VaultStore::new(blocked.join("v.vault"), "test", "test");
    assert!(
        do_restore_password_history(&state, &id, &before.password_history[0].id.to_string())
            .is_err()
    );
    assert_eq!(
        guard(&state)
            .unwrap()
            .vault()
            .unwrap()
            .get_item(parse_id(&id).unwrap())
            .unwrap(),
        before
    );
}

#[test]
fn failed_writes_restore_items_revisions_and_deletions() {
    let dir = TempDir::new().unwrap();
    let (state, _probe) = unlocked(&dir);
    let id = do_upsert_item(&state, sample_input()).unwrap();
    let uuid = Uuid::parse_str(&id).unwrap();
    let before = guard(&state)
        .unwrap()
        .vault()
        .unwrap()
        .get_item(uuid)
        .unwrap();
    let blocked = dir.path().join("blocked");
    std::fs::write(&blocked, b"not a directory").unwrap();
    guard(&state).unwrap().store = VaultStore::new(blocked.join("v.vault"), "svc", "acct");

    assert!(do_upsert_item(&state, sample_input()).is_err());
    assert_eq!(do_list_items(&state, true).unwrap().len(), 1);
    let mut edit = sample_input();
    edit.id = Some(id.clone());
    edit.password = "not persisted".into();
    assert!(do_upsert_item(&state, edit).is_err());
    assert!(do_delete_item(&state, &id).is_err());
    assert!(do_purge_item(&state, &id).is_err());
    assert_eq!(
        guard(&state)
            .unwrap()
            .vault()
            .unwrap()
            .get_item(uuid)
            .unwrap(),
        before
    );

    // Retrying after the filesystem recovers must commit exactly once.
    guard(&state).unwrap().store = VaultStore::new(dir.path().join("v.vault"), "svc", "acct");
    do_delete_item(&state, &id).unwrap();
    let deleted = guard(&state)
        .unwrap()
        .vault()
        .unwrap()
        .get_item(uuid)
        .unwrap();
    guard(&state).unwrap().store = VaultStore::new(blocked.join("v.vault"), "svc", "acct");
    assert!(do_restore_item(&state, &id).is_err());
    assert_eq!(
        guard(&state)
            .unwrap()
            .vault()
            .unwrap()
            .get_item(uuid)
            .unwrap(),
        deleted
    );
}

#[test]
fn create_then_wrong_then_right_unlock() {
    let dir = TempDir::new().unwrap();
    let store = VaultStore::new(dir.path().join("v.vault"), "svc", "acct");
    let (clip, _) = ClipboardManager::memory();
    let state = Mutex::new(AppState::new(store, None, clip));

    assert!(matches!(
        do_create_vault(&state, "short"),
        Err(e) if e.code == "weak_password"
    ));
    assert!(!guard(&state).unwrap().store.exists());
    do_create_vault(&state, "masterpw").unwrap(); // production KDF; one test
    assert!(guard(&state).unwrap().vault().unwrap().is_unlocked());

    guard(&state).unwrap().vault_mut().unwrap().lock().unwrap();
    assert!(matches!(do_unlock(&state, "nope"), Err(e) if e.code == "invalid_credentials"));
    do_unlock(&state, "masterpw").unwrap();
    assert!(guard(&state).unwrap().vault().unwrap().is_unlocked());
}

#[test]
fn upsert_list_get_roundtrip_with_dto_flags() {
    let dir = TempDir::new().unwrap();
    let (state, _probe) = unlocked(&dir);

    let id = do_upsert_item(&state, sample_input()).unwrap();
    let list = do_list_items(&state, false).unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].title, "GitHub");
    assert_eq!(list[0].letter, "G");
    assert!(list[0].has_totp);

    let detail = do_get_item(&state, &id).unwrap();
    assert_eq!(detail.username, "frank-lia");
    assert_eq!(detail.url, "https://github.com");
    assert!(detail.has_password);
    assert!(detail.has_totp);
    // The detail DTO has no field that could carry the password/secret.
}

#[test]
fn list_items_reports_the_normalized_host_for_grouping() {
    let dir = TempDir::new().unwrap();
    let (state, _) = unlocked(&dir);

    // Messy-but-equivalent URLs normalize to the same host; no URL -> "".
    let mut a = sample_input();
    a.title = "GitHub (work)".into();
    a.url = "https://www.github.com/login?next=/".into();
    do_upsert_item(&state, a).unwrap();
    let mut b = sample_input();
    b.title = "GitHub (privat)".into();
    b.url = "github.com".into();
    do_upsert_item(&state, b).unwrap();
    let mut c = sample_input();
    c.title = "Uten nettsted".into();
    c.url = String::new();
    do_upsert_item(&state, c).unwrap();

    let list = do_list_items(&state, false).unwrap();
    let host_by_title = |t: &str| {
        list.iter()
            .find(|i| i.title == t)
            .map(|i| i.host.clone())
            .unwrap()
    };
    assert_eq!(host_by_title("GitHub (work)"), "github.com");
    assert_eq!(host_by_title("GitHub (privat)"), "github.com");
    assert_eq!(host_by_title("Uten nettsted"), "");
}

#[test]
fn editing_preserves_created_at() {
    let dir = TempDir::new().unwrap();
    let (state, _) = unlocked(&dir);
    let id = do_upsert_item(&state, sample_input()).unwrap();
    let created = do_get_item(&state, &id).unwrap().created_at;

    let mut edit = sample_input();
    edit.id = Some(id.clone());
    edit.title = "GitHub (work)".into();
    do_upsert_item(&state, edit).unwrap();

    let after = do_get_item(&state, &id).unwrap();
    assert_eq!(after.title, "GitHub (work)");
    assert_eq!(after.created_at, created); // preserved on edit
    assert!(after.modified_at >= created);
}

#[test]
fn login_editor_cannot_replace_a_passkey() {
    let dir = TempDir::new().unwrap();
    let (state, _) = unlocked(&dir);
    let passkey = Item::new(
        VaultItem::Passkey {
            title: "github.com".into(),
            rp_id: "github.com".into(),
            user_name: "frank".into(),
            user_handle: vec![1, 2, 3],
            credential_id: vec![4, 5, 6],
            private_key: vec![7; 32],
            sign_count: 0,
        },
        now_millis(),
    );
    let id = passkey.id;
    guard(&state)
        .unwrap()
        .vault_mut()
        .unwrap()
        .upsert_item(passkey.clone())
        .unwrap();

    let mut input = sample_input();
    input.id = Some(id.to_string());
    assert!(matches!(
        do_upsert_item(&state, input),
        Err(e) if e.code == "item_kind_mismatch"
    ));

    let stored = guard(&state)
        .unwrap()
        .vault()
        .unwrap()
        .get_item(id)
        .unwrap();
    assert_eq!(stored.id, passkey.id);
    assert_eq!(stored.created_at, passkey.created_at);
    match &stored.data {
        VaultItem::Passkey {
            credential_id,
            private_key,
            ..
        } => {
            assert_eq!(credential_id, &vec![4, 5, 6]);
            assert_eq!(private_key, &vec![7; 32]);
        }
        _ => panic!("passkey was replaced by another item type"),
    }
}

#[test]
fn bookmark_editor_normalizes_folders_and_preserves_item_type() {
    let dir = TempDir::new().unwrap();
    let (state, _) = unlocked(&dir);
    let id = do_upsert_bookmark(
        &state,
        BookmarkInput {
            id: None,
            title: String::new(),
            url: "example.com/path".into(),
            folder: " / Work // Projects / ".into(),
            notes: "reference material".into(),
        },
    )
    .unwrap();

    let detail = do_get_item(&state, &id).unwrap();
    assert_eq!(detail.kind, "bookmark");
    assert_eq!(detail.title, "example.com");
    assert_eq!(detail.folder, "Work/Projects");
    assert_eq!(detail.url, "https://example.com/path");

    let login_id = do_upsert_item(&state, sample_input()).unwrap();
    assert!(matches!(
        do_upsert_bookmark(
            &state,
            BookmarkInput {
                id: Some(login_id),
                title: "Wrong editor".into(),
                url: "https://example.org".into(),
                folder: String::new(),
                notes: String::new(),
            },
        ),
        Err(e) if e.code == "item_kind_mismatch"
    ));
}

#[test]
fn bulk_move_is_validated_and_searches_notes_without_returning_them() {
    let dir = TempDir::new().unwrap();
    let (state, _) = unlocked(&dir);
    let bookmark_id = do_upsert_bookmark(
        &state,
        BookmarkInput {
            id: None,
            title: "Rust".into(),
            url: "https://rust-lang.org".into(),
            folder: "Reading".into(),
            notes: "ownership reference".into(),
        },
    )
    .unwrap();
    let login_id = do_upsert_item(&state, sample_input()).unwrap();

    assert!(matches!(
        do_move_bookmarks(
            &state,
            vec![bookmark_id.clone(), login_id],
            "Archive"
        ),
        Err(e) if e.code == "item_kind_mismatch"
    ));
    assert_eq!(do_get_item(&state, &bookmark_id).unwrap().folder, "Reading");

    assert_eq!(
        do_move_bookmarks(&state, vec![bookmark_id.clone()], " / Work // Rust ").unwrap(),
        1
    );
    assert_eq!(
        do_get_item(&state, &bookmark_id).unwrap().folder,
        "Work/Rust"
    );
    assert_eq!(
        do_search_items(&state, "OWNERSHIP", false).unwrap(),
        vec![bookmark_id]
    );
}

#[test]
fn encrypted_backup_is_fully_verified_before_restore() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("backup.vault");
    let backup = Vault::create("backup-password", cheap_params()).unwrap();
    std::fs::write(&path, backup.to_bytes().unwrap()).unwrap();

    let candidate = load_backup_candidate(&path, "backup-password".to_string()).unwrap();
    assert!(candidate.is_unlocked());
    assert!(!candidate.has_device_unlock());

    assert!(matches!(
        load_backup_candidate(&path, "wrong-password".to_string()),
        Err(e) if e.code == "invalid_credentials"
    ));

    let garbage = dir.path().join("garbage.vault");
    std::fs::write(&garbage, b"not a vault").unwrap();
    assert!(load_backup_candidate(&garbage, "anything".to_string()).is_err());
}

#[test]
fn reveal_and_copy_route_the_correct_secret() {
    let dir = TempDir::new().unwrap();
    let (state, probe) = unlocked(&dir);
    let id = do_upsert_item(&state, sample_input()).unwrap();

    assert_eq!(do_reveal_field(&state, &id, "password").unwrap(), "p4ss");

    do_copy_field(&state, &id, "password").unwrap();
    // Flush the clipboard owner thread, then confirm it still holds the
    // value after the command returned (the ownership-drop guard).
    guard(&state).unwrap().clipboard.sync();
    assert_eq!(probe.current().as_deref(), Some("p4ss"));
}

#[test]
fn soft_delete_restore_then_purge() {
    let dir = TempDir::new().unwrap();
    let (state, _) = unlocked(&dir);
    let id = do_upsert_item(&state, sample_input()).unwrap();

    do_delete_item(&state, &id).unwrap();
    assert_eq!(do_list_items(&state, false).unwrap().len(), 0);
    assert_eq!(do_list_items(&state, true).unwrap().len(), 1);

    do_restore_item(&state, &id).unwrap();
    assert_eq!(do_list_items(&state, false).unwrap().len(), 1);

    do_delete_item(&state, &id).unwrap();
    do_purge_item(&state, &id).unwrap();
    assert_eq!(do_list_items(&state, true).unwrap().len(), 0);
}

#[test]
fn item_ops_require_an_unlocked_vault() {
    let dir = TempDir::new().unwrap();
    let store = VaultStore::new(dir.path().join("v.vault"), "svc", "acct");
    let (clip, _) = ClipboardManager::memory();
    let locked = {
        let mut v = Vault::create("pw", cheap_params()).unwrap();
        v.lock().unwrap();
        v
    };
    let state = Mutex::new(AppState::new(store, Some(locked), clip));
    assert!(matches!(do_list_items(&state, false), Err(e) if e.code == "locked"));
}

#[test]
fn persisted_changes_survive_reload() {
    let dir = TempDir::new().unwrap();
    let (state, _) = unlocked(&dir);
    let id = do_upsert_item(&state, sample_input()).unwrap();

    // Reload the vault file from disk into a fresh state and unlock it.
    let store = VaultStore::new(dir.path().join("v.vault"), "svc", "acct");
    let (clip, _) = ClipboardManager::memory();
    let reloaded = Mutex::new(AppState::new(store, None, clip));
    do_unlock(&reloaded, "pw").unwrap();

    assert_eq!(do_get_item(&reloaded, &id).unwrap().title, "GitHub");
}

#[test]
fn get_item_reports_password_strength() {
    let dir = TempDir::new().unwrap();
    let (state, _) = unlocked(&dir);

    let weak_id = do_upsert_item(&state, sample_input()).unwrap(); // "p4ss"
    assert_eq!(
        do_get_item(&state, &weak_id)
            .unwrap()
            .password_strength
            .as_deref(),
        Some("weak")
    );

    let mut strong = sample_input();
    strong.password = "wf*QB(=0QIc0.Z^RI,A6".into();
    let strong_id = do_upsert_item(&state, strong).unwrap();
    assert_eq!(
        do_get_item(&state, &strong_id)
            .unwrap()
            .password_strength
            .as_deref(),
        Some("strong")
    );
}

#[test]
fn upsert_accepts_otpauth_uri_and_stores_base32_secret() {
    let dir = TempDir::new().unwrap();
    let (state, _) = unlocked(&dir);

    let mut input = sample_input();
    input.totp_secret = Some(
        "otpauth://totp/GitHub:frank?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=GitHub".into(),
    );
    let id = do_upsert_item(&state, input).unwrap();

    assert!(do_get_item(&state, &id).unwrap().has_totp);
    // The stored secret is the extracted Base32, not the raw URI.
    assert_eq!(
        do_reveal_field(&state, &id, "totp_secret").unwrap(),
        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    );
}

#[test]
fn upsert_rejects_otpauth_with_unsupported_params() {
    let dir = TempDir::new().unwrap();
    let (state, _) = unlocked(&dir);
    let mut input = sample_input();
    input.totp_secret = Some("otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ&digits=8".into());
    assert!(matches!(do_upsert_item(&state, input), Err(e) if e.code == "invalid_argument"));
}

#[test]
fn security_report_flags_weak_and_reused() {
    let dir = TempDir::new().unwrap();
    let (state, _) = unlocked(&dir);

    // Two items share a strong password (reused), one item is weak.
    let mut a = sample_input();
    a.title = "A".into();
    a.password = "Sh4red&Strong!2024xyz".into();
    let a_id = do_upsert_item(&state, a).unwrap();

    let mut b = sample_input();
    b.title = "B".into();
    b.password = "Sh4red&Strong!2024xyz".into();
    do_upsert_item(&state, b).unwrap();

    let mut c = sample_input();
    c.title = "C".into();
    c.password = "abc".into();
    do_upsert_item(&state, c).unwrap();

    let report = do_security_report(&state).unwrap();
    // A + B flagged reused; C flagged weak. (sample_input's TOTP doesn't matter.)
    assert_eq!(report.len(), 3);
    let a_issues = &report.iter().find(|r| r.id == a_id).unwrap().issues;
    assert!(a_issues.contains(&"reused".to_string()));
}

#[test]
fn parse_chrome_csv() {
    let csv = "name,url,username,password,note\n\
               GitHub,https://github.com,frank-lia,p4ss,my note\n\
               ,https://x.com/login,user2,pw2,\n";
    let (logins, skipped) = parse_logins_csv(csv);
    assert_eq!(skipped, 0);
    assert_eq!(logins.len(), 2);
    assert_eq!(logins[0].title, "GitHub");
    assert_eq!(logins[0].username, "frank-lia");
    assert_eq!(logins[0].notes, "my note");
    // No title column value -> derived from the URL host.
    assert_eq!(logins[1].title, "x.com");
}

#[test]
fn parse_apple_csv_keeps_otpauth_and_skips_blank_rows() {
    let csv = "Title,URL,Username,Password,Notes,OTPAuth\n\
               Bank,https://bank.com,me,secret,\"a, b\",otpauth://totp/Bank?secret=GEZDGNBVGY3TQOJQ\n\
               ,,,,,\n";
    let (logins, skipped) = parse_logins_csv(csv);
    assert_eq!(logins.len(), 1);
    assert_eq!(skipped, 1); // the empty row
    assert_eq!(logins[0].notes, "a, b"); // quoted comma preserved
    assert!(logins[0].totp.starts_with("otpauth://"));
}

#[test]
fn do_import_logins_adds_items_and_normalizes_totp() {
    let dir = TempDir::new().unwrap();
    let (state, _) = unlocked(&dir);
    let csv_path = dir.path().join("export.csv");
    std::fs::write(
        &csv_path,
        "Title,URL,Username,Password,OTPAuth\n\
         Bank,https://bank.com,me,secret,otpauth://totp/Bank?secret=GEZDGNBVGY3TQOJQ\n\
         Mail,https://mail.com,you,hunter2,\n\
         ,,,,\n",
    )
    .unwrap();

    let summary = do_import_logins(&state, csv_path.to_str().unwrap()).unwrap();
    assert_eq!(summary.imported, 2);
    assert_eq!(summary.skipped, 1);

    let list = do_list_items(&state, false).unwrap();
    assert_eq!(list.len(), 2);
    let bank = list.iter().find(|i| i.title == "Bank").unwrap();
    assert!(bank.has_totp); // otpauth normalized to a stored secret
}

#[test]
fn reimport_dedupes_and_updates_instead_of_duplicating() {
    let dir = TempDir::new().unwrap();
    let (state, _) = unlocked(&dir);
    let write = |name: &str, body: &str| {
        let p = dir.path().join(name);
        std::fs::write(&p, body).unwrap();
        p
    };

    let first = write(
        "a.csv",
        "name,url,username,password,otpauth,notes\n\
         Bank,https://www.bank.com/login,Me@Bank.com,old-secret,otpauth://totp/Bank?secret=GEZDGNBVGY3TQOJQ,viktig notat\n\
         NoUrl,,someone,pw1,,\n",
    );
    let s1 = do_import_logins(&state, first.to_str().unwrap()).unwrap();
    assert_eq!((s1.imported, s1.updated, s1.duplicates), (2, 0, 0));
    let bank_id = do_list_items(&state, false)
        .unwrap()
        .into_iter()
        .find(|i| i.title == "Bank")
        .unwrap()
        .id;

    // Re-import: same login (messier URL + different username case) with an
    // unchanged password is a duplicate; a changed password updates the
    // EXISTING item; a URL-less row never merges.
    let second = write(
        "b.csv",
        "name,url,username,password\n\
         Bank,bank.com,me@bank.com,old-secret\n\
         NoUrl,,someone,pw1\n",
    );
    let s2 = do_import_logins(&state, second.to_str().unwrap()).unwrap();
    assert_eq!((s2.imported, s2.updated, s2.duplicates), (1, 0, 1));

    let third = write(
        "c.csv",
        "name,url,username,password\n\
         Bank,https://bank.com,me@bank.com,NEW-secret\n",
    );
    let s3 = do_import_logins(&state, third.to_str().unwrap()).unwrap();
    assert_eq!((s3.imported, s3.updated, s3.duplicates), (0, 1, 0));

    // Still one Bank item, same id, with the new password — and the TOTP +
    // notes from the first import survive (the update CSV had neither).
    let list = do_list_items(&state, false).unwrap();
    assert_eq!(list.iter().filter(|i| i.title == "Bank").count(), 1);
    let bank = list.iter().find(|i| i.title == "Bank").unwrap();
    assert_eq!(bank.id, bank_id);
    assert_eq!(
        do_reveal_field(&state, &bank.id, "password").unwrap(),
        "NEW-secret"
    );
    assert!(bank.has_totp);
    assert_eq!(
        do_reveal_field(&state, &bank.id, "notes").unwrap(),
        "viktig notat"
    );

    // The user's title + full URL are preserved on update — not clobbered
    // by the export's synthesized/bare values.
    let detail = do_get_item(&state, &bank.id).unwrap();
    assert_eq!(detail.title, "Bank");
    assert_eq!(detail.url, "https://www.bank.com/login");

    // Two same-key rows within ONE file: first imports, second dedupes.
    let fourth = write(
        "d.csv",
        "name,url,username,password\n\
         Shop,https://shop.no,kunde,pw\n\
         Shop,https://www.shop.no,KUNDE,pw\n",
    );
    let s4 = do_import_logins(&state, fourth.to_str().unwrap()).unwrap();
    assert_eq!((s4.imported, s4.updated, s4.duplicates), (1, 0, 1));

    // A row with a BLANK password must never wipe the stored password: it's
    // a no-op (duplicate), not a destructive update.
    let blank = write(
        "e.csv",
        "name,url,username,password\n\
         Bank,https://bank.com,me@bank.com,\n",
    );
    let s5 = do_import_logins(&state, blank.to_str().unwrap()).unwrap();
    assert_eq!((s5.imported, s5.updated, s5.duplicates), (0, 0, 1));
    assert_eq!(
        do_reveal_field(&state, &bank.id, "password").unwrap(),
        "NEW-secret" // untouched
    );

    // Same password but a NEWLY populated TOTP column must MERGE into the
    // existing entry (Shop had none), not be dropped as a "duplicate".
    let shop_id = do_list_items(&state, false)
        .unwrap()
        .into_iter()
        .find(|i| i.title == "Shop")
        .unwrap()
        .id;
    assert!(
        !do_list_items(&state, false)
            .unwrap()
            .iter()
            .find(|i| i.id == shop_id)
            .unwrap()
            .has_totp
    );
    let shop_totp = write(
        "g.csv",
        "name,url,username,password,otpauth\n\
         Shop,https://shop.no,kunde,pw,otpauth://totp/Shop?secret=GEZDGNBVGY3TQOJQ\n",
    );
    let s6 = do_import_logins(&state, shop_totp.to_str().unwrap()).unwrap();
    assert_eq!((s6.imported, s6.updated, s6.duplicates), (0, 1, 0));
    assert!(
        do_list_items(&state, false)
            .unwrap()
            .iter()
            .find(|i| i.id == shop_id)
            .unwrap()
            .has_totp
    );
}

#[test]
fn import_bookmarks_adds_new_and_ignores_duplicates() {
    let dir = TempDir::new().unwrap();
    let (state, _) = unlocked(&dir);

    let bookmarks_file = dir.path().join("Bookmarks");
    std::fs::write(
        &bookmarks_file,
        r#"{
            "roots": {
                "bookmark_bar": {
                    "children": [
                        {
                            "type": "url",
                            "name": "Documentation",
                            "url": "https://docs.example.com"
                        }
                    ],
                    "name": "Bookmarks bar",
                    "type": "folder"
                }
            },
            "version": 1
        }"#,
    )
    .unwrap();

    let added = do_import_bookmarks(&state, &bookmarks_file).unwrap();
    assert_eq!(added, 1);

    // Second import of same file: duplicate is skipped
    let added_again = do_import_bookmarks(&state, &bookmarks_file).unwrap();
    assert_eq!(added_again, 0);

    let items = do_list_items(&state, false).unwrap();
    let doc = items.iter().find(|i| i.title == "Documentation").unwrap();
    assert_eq!(doc.kind, "bookmark");
}

#[test]
fn import_bookmarks_requires_unlocked_vault_and_valid_file() {
    let dir = TempDir::new().unwrap();
    let store = VaultStore::new(dir.path().join("v.vault"), "svc", "acct");
    let (clip, _) = ClipboardManager::memory();
    let locked_state = Mutex::new(AppState::new(store, None, clip));

    let non_existent = dir.path().join("does_not_exist.json");
    let err = do_import_bookmarks(&locked_state, &non_existent).unwrap_err();
    assert_eq!(err.code, "read_failed");

    let empty_file = dir.path().join("empty.json");
    std::fs::write(&empty_file, b"{}").unwrap();
    let err_locked = do_import_bookmarks(&locked_state, &empty_file).unwrap_err();
    assert_eq!(err_locked.code, "no_vault");
}
