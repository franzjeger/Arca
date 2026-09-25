use vault_core::{Item, KdfParams, Vault, VaultItem};

fn vault() -> Vault {
    let mut params = KdfParams::new_default().unwrap();
    params.m_cost_kib = 256;
    params.t_cost = 1;
    Vault::create("master", params).unwrap()
}

fn login() -> Item {
    Item::new(
        VaultItem::Login {
            title: "Site".into(),
            username: "account".into(),
            password: "original-secret".into(),
            url: "https://example.test".into(),
            notes: "keep notes".into(),
            totp_secret: None,
        },
        1,
    )
}

fn edit(v: &mut Vault, id: uuid::Uuid, password: &str, now: i64) {
    let mut item = v.get_item(id).unwrap();
    if let VaultItem::Login { password: p, .. } = &mut item.data {
        *p = password.into();
    }
    // Model a DTO / older V5 peer that knows nothing about the history field.
    item.password_history.clear();
    item.modified_at = now;
    v.upsert_item(item).unwrap();
}

#[test]
fn history_is_encrypted_persists_and_restores_only_the_selected_password() {
    let mut v = vault();
    let item = login();
    let id = item.id;
    v.upsert_item(item).unwrap();
    edit(&mut v, id, "new-secret", 2);
    let bytes = v.to_bytes().unwrap();
    assert!(!bytes
        .windows(b"original-secret".len())
        .any(|w| w == b"original-secret"));
    v = Vault::from_bytes(&bytes).unwrap();
    v.unlock("master").unwrap();
    let current = v.get_item(id).unwrap();
    assert_eq!(current.password_history.len(), 1);
    assert_eq!(current.password_history[0].password, "original-secret");
    assert!(!format!("{current:?}").contains("original-secret"));
    v.restore_password(id, current.password_history[0].id, 3)
        .unwrap();
    let restored = v.get_item(id).unwrap();
    assert_eq!(restored.password(), Some("original-secret"));
    assert_eq!(restored.password_history[0].password, "new-secret");
    if let VaultItem::Login {
        username,
        url,
        notes,
        ..
    } = &restored.data
    {
        assert_eq!(username, "account");
        assert_eq!(notes, "keep notes");
        assert_eq!(url, "https://example.test");
    } else {
        panic!("kind changed");
    }
    v.lock().unwrap();
    assert!(v
        .restore_password(id, current.password_history[0].id, 4)
        .is_err());
}

#[test]
fn unchanged_password_does_not_add_history_and_retention_is_bounded() {
    let mut v = vault();
    let item = login();
    let id = item.id;
    v.upsert_item(item).unwrap();
    edit(&mut v, id, "original-secret", 2);
    assert!(v.get_item(id).unwrap().password_history.is_empty());
    for i in 3..35 {
        edit(&mut v, id, &format!("value-{i}"), i);
    }
    let item = v.get_item(id).unwrap();
    assert_eq!(item.password_history.len(), 20);
    assert_eq!(item.password_history[0].password, "value-33");
    assert_eq!(item.password_history[19].password, "value-14");
}

#[test]
fn sync_preserves_both_concurrent_passwords_and_history_without_duplicates() {
    let mut a = vault();
    let item = login();
    let id = item.id;
    a.upsert_item(item).unwrap();
    let mut b = Vault::from_bytes(&a.to_bytes().unwrap()).unwrap();
    b.unlock("master").unwrap();
    edit(&mut a, id, "desktop-secret", 2);
    edit(&mut b, id, "phone-secret", 3);
    let remote = b.to_bytes().unwrap();
    a.merge_remote(&remote).unwrap();
    let once = a.get_item(id).unwrap();
    a.merge_remote(&remote).unwrap();
    assert_eq!(
        a.get_item(id).unwrap().password_history,
        once.password_history
    );
    assert!(once
        .password_history
        .iter()
        .any(|h| h.password == "original-secret"));
    assert!(once
        .password_history
        .iter()
        .any(|h| h.password == "desktop-secret"));
    assert_eq!(once.password(), Some("phone-secret"));
}

#[test]
fn old_item_payloads_without_history_still_decode() {
    let mut json = serde_json::to_value(login()).unwrap();
    json.as_object_mut().unwrap().remove("password_history");
    let old: Item = serde_json::from_value(json).unwrap();
    assert!(old.password_history.is_empty());
}

#[test]
fn a_backwards_clock_does_not_discard_the_password_just_replaced() {
    let mut v = vault();
    let item = login();
    let id = item.id;
    v.upsert_item(item).unwrap();
    for i in 2..30 {
        edit(&mut v, id, &format!("value-{i}"), i);
    }
    edit(&mut v, id, "new with backwards clock", -100);
    assert_eq!(
        v.get_item(id).unwrap().password_history[0].password,
        "value-29"
    );
}
