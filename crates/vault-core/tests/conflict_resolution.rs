use vault_core::{conflicts::Resolution, item::SyncConflict, Item, KdfParams, Vault, VaultItem};

fn fixture() -> (Vault, Item, Item) {
    let mut params = KdfParams::new_default().unwrap();
    params.m_cost_kib = 256;
    params.t_cost = 1;
    params.p_cost = 1;
    let mut vault = Vault::create("master", params).unwrap();
    let original = Item::new(
        VaultItem::Login {
            title: "Account".into(),
            username: "original-user".into(),
            password: "original-password".into(),
            url: "https://example.com".into(),
            totp_secret: Some("ORIGINALOTP".into()),
            notes: "original notes".into(),
        },
        1,
    );
    let mut copy = Item::new(
        VaultItem::Login {
            title: "Account (sync conflict)".into(),
            username: "copy-user".into(),
            password: "copy-password".into(),
            url: "https://example.org".into(),
            totp_secret: Some("COPYOTP".into()),
            notes: "copy notes".into(),
        },
        2,
    );
    copy.sync_conflict = Some(SyncConflict {
        original_id: original.id,
        original_title: "Account".into(),
        resolved: false,
    });
    vault.upsert_item(original.clone()).unwrap();
    vault.upsert_item(copy.clone()).unwrap();
    (vault, original, copy)
}

#[test]
fn field_merge_keeps_selected_secrets_and_archives_both_inputs() {
    let (mut vault, original, copy) = fixture();
    let stale_peer = vault.to_bytes().unwrap();
    vault
        .resolve_sync_conflict(
            original.id,
            copy.id,
            (original.revision, copy.revision),
            Resolution::Merge,
            &["password".into(), "notes".into()],
            10,
        )
        .unwrap();
    let combined = vault.get_item(original.id).unwrap();
    let VaultItem::Login {
        username,
        password,
        url,
        totp_secret,
        notes,
        ..
    } = &combined.data
    else {
        panic!()
    };
    assert_eq!(username, "original-user");
    assert_eq!(password, "copy-password");
    assert_eq!(url, "https://example.com");
    assert_eq!(totp_secret.as_deref(), Some("ORIGINALOTP"));
    assert_eq!(notes, "copy notes");
    assert!(combined
        .password_history
        .iter()
        .any(|entry| entry.password == "original-password"));
    let summaries = vault.list_items(true).unwrap();
    assert_eq!(summaries.len(), 3);
    assert!(summaries.iter().all(|item| !item.is_sync_conflict));
    let archived: Vec<_> = summaries
        .iter()
        .filter(|item| item.is_deleted)
        .map(|item| vault.get_item(item.id).unwrap())
        .collect();
    assert!(archived.iter().any(|item| item.data == original.data));
    assert!(archived
        .iter()
        .any(|item| item.password() == Some("copy-password")));
    vault.merge_remote(&stale_peer).unwrap();
    assert!(vault
        .list_items(true)
        .unwrap()
        .iter()
        .all(|item| !item.is_sync_conflict));
    let encrypted = vault.to_bytes().unwrap();
    assert!(!encrypted
        .windows(b"copy-password".len())
        .any(|window| window == b"copy-password"));
    let mut reopened = Vault::from_bytes(&encrypted).unwrap();
    reopened.unlock("master").unwrap();
    assert_eq!(
        reopened.get_item(original.id).unwrap().password(),
        Some("copy-password")
    );
}

#[test]
fn stale_wrong_pair_and_unknown_fields_are_rejected_without_changes() {
    let (mut vault, original, copy) = fixture();
    let before = vault.list_items(true).unwrap().len();
    for (id, revisions, fields) in [
        (copy.id, (original.revision, copy.revision), vec![]),
        (original.id, (uuid::Uuid::new_v4(), copy.revision), vec![]),
        (
            original.id,
            (original.revision, copy.revision),
            vec!["private_key".into()],
        ),
    ] {
        assert!(vault
            .resolve_sync_conflict(id, copy.id, revisions, Resolution::Merge, &fields, 10)
            .is_err());
        assert_eq!(vault.list_items(true).unwrap().len(), before);
        assert_eq!(vault.get_item(original.id).unwrap(), original);
        assert_eq!(vault.get_item(copy.id).unwrap(), copy);
    }
}

#[test]
fn keep_both_supports_legacy_copies_and_survives_a_stale_peer() {
    let (mut vault, original, mut copy) = fixture();
    let mut legacy = vault_core::conflicts::merge_payload(&original, &copy, &[]).unwrap();
    vault_core::conflicts::set_title(&mut legacy, "Account (sync conflict)".into());
    // Insert a separate legacy copy, without guessing an original by title.
    copy = Item::new(legacy, 2);
    vault.upsert_item(copy.clone()).unwrap();
    let stale = vault.to_bytes().unwrap();
    vault
        .resolve_sync_conflict(
            original.id,
            copy.id,
            (original.revision, copy.revision),
            Resolution::KeepBoth,
            &[],
            10,
        )
        .unwrap();
    let kept = vault.get_item(copy.id).unwrap();
    assert_eq!(kept.data.title(), "Account");
    assert!(!kept.is_deleted());
    assert!(!kept.is_sync_conflict());
    vault.merge_remote(&stale).unwrap();
    assert!(!vault.get_item(copy.id).unwrap().is_sync_conflict());
}

#[test]
fn deletion_is_an_explicit_field_and_original_is_preserved() {
    let (mut vault, original, mut copy) = fixture();
    vault.delete_item(copy.id, 3).unwrap();
    copy = vault.get_item(copy.id).unwrap();
    vault
        .resolve_sync_conflict(
            original.id,
            copy.id,
            (original.revision, copy.revision),
            Resolution::UseCopy,
            &[],
            10,
        )
        .unwrap();
    let result = vault.get_item(original.id).unwrap();
    assert!(result.is_deleted());
    assert_eq!(result.password(), Some("copy-password"));
    assert_eq!(result.data.title(), "Account");
}

#[test]
fn sync_creates_a_persisted_original_link() {
    let (mut left, original, _) = fixture();
    let mut right = Vault::from_bytes(&left.to_bytes().unwrap()).unwrap();
    right.unlock("master").unwrap();
    let mut a = original.clone();
    let mut b = original.clone();
    vault_core::conflicts::set_title(&mut a.data, "Left edit".into());
    vault_core::conflicts::set_title(&mut b.data, "Right edit".into());
    a.modified_at = 5;
    b.modified_at = 6;
    left.upsert_item(a).unwrap();
    right.upsert_item(b).unwrap();
    left.merge_remote(&right.to_bytes().unwrap()).unwrap();
    assert!(left
        .list_items(true)
        .unwrap()
        .iter()
        .any(|item| item.title == "Left edit (sync conflict)"
            && item.conflict_of == Some(original.id)));
}

#[test]
fn credentials_are_kept_as_complete_units() {
    let original = Item::new(
        VaultItem::Passkey {
            title: "Original name".into(),
            rp_id: "example.com".into(),
            user_name: "alice".into(),
            user_handle: vec![1],
            credential_id: vec![2],
            private_key: vec![3; 32],
            sign_count: 0,
        },
        1,
    );
    let mut copy = Item::new(
        VaultItem::Passkey {
            title: "Other name (sync conflict)".into(),
            rp_id: "example.org".into(),
            user_name: "bob".into(),
            user_handle: vec![4],
            credential_id: vec![5],
            private_key: vec![6; 32],
            sign_count: 1,
        },
        2,
    );
    copy.sync_conflict = Some(SyncConflict {
        original_id: original.id,
        original_title: "Other name".into(),
        resolved: false,
    });
    let merged =
        vault_core::conflicts::merge_payload(&original, &copy, &["credential".into()]).unwrap();
    let mut expected = copy.data.clone();
    vault_core::conflicts::set_title(&mut expected, "Original name".into());
    assert_eq!(merged, expected);
    assert!(
        vault_core::conflicts::merge_payload(&original, &copy, &["private_key".into()]).is_err()
    );
}

#[test]
fn an_orphan_conflict_can_be_kept_without_losing_its_contents() {
    let (mut vault, original, copy) = fixture();
    vault.purge_item(original.id, 5).unwrap();
    vault.keep_sync_conflict_copy(copy.id, 10).unwrap();
    let kept = vault.get_item(copy.id).unwrap();
    assert_eq!(kept.password(), copy.password());
    assert_eq!(kept.data.title(), "Account");
    assert!(!kept.is_deleted());
    assert!(!kept.is_sync_conflict());
    assert!(vault.get_item(original.id).is_err());
}
