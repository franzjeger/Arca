//! Can a client that predates a new item kind still read the vault?
//!
//! The on-disk item payload is CBOR tagged by variant NAME, which makes adding
//! a kind safe for a NEW client reading OLD data. It says nothing about the
//! other direction, and the other direction is the one that ships: a phone
//! updates through review, a desktop updates from a script, and for days the
//! two are not the same build.
use serde::{Deserialize, Serialize};

/// The enum as an OLDER build knows it: every variant except Bookmark.
#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
enum OldVaultItem {
    Login {
        title: String,
        username: String,
        password: String,
        url: String,
        totp_secret: Option<String>,
        notes: String,
    },
    Passkey {
        title: String,
    },
    SshKey {
        title: String,
    },
    Wifi {
        title: String,
    },
    SecureNote {
        title: String,
        body: String,
    },
}

/// The enum as a FUTURE build will know it: one kind this build has never
/// heard of, alongside one it has.
#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(tag = "type")]
enum FutureVaultItem {
    SecureNote {
        title: String,
        body: String,
    },
    CreditCard {
        title: String,
        number: String,
        cvv: String,
    },
}

fn cbor<T: Serialize>(v: &T) -> Vec<u8> {
    let mut b = Vec::new();
    ciborium::into_writer(v, &mut b).unwrap();
    b
}

#[test]
fn this_build_reads_a_kind_it_has_never_heard_of() {
    let future = FutureVaultItem::CreditCard {
        title: "Visa".into(),
        number: "4111111111111111".into(),
        cvv: "123".into(),
    };
    let got: vault_core::VaultItem = ciborium::from_reader(&cbor(&future)[..])
        .expect("an unknown kind must not fail the decode");
    match &got {
        vault_core::VaultItem::Unknown(u) => assert_eq!(u.kind, "CreditCard"),
        other => panic!("expected Unknown, got {other:?}"),
    }
}

#[test]
fn and_writes_it_back_byte_for_byte() {
    // Tolerating an unknown kind is only half the job. A client that read the
    // vault, dropped what it could not name, and saved would DELETE the newer
    // entries — so what goes out must equal what came in.
    let original = cbor(&FutureVaultItem::CreditCard {
        title: "Visa".into(),
        number: "4111111111111111".into(),
        cvv: "123".into(),
    });
    let held: vault_core::VaultItem = ciborium::from_reader(&original[..]).unwrap();
    assert_eq!(
        cbor(&held),
        original,
        "the bytes must survive the round trip"
    );
}

#[test]
fn one_unknown_no_longer_takes_the_list_with_it() {
    // The real shape, and the whole point: the vault decodes every item at
    // once. Before the Unknown variant, one entry of an unrecognised kind
    // failed the decode of EVERY entry in the file.
    let items = vec![
        FutureVaultItem::SecureNote {
            title: "Note".into(),
            body: "keep me".into(),
        },
        FutureVaultItem::CreditCard {
            title: "Visa".into(),
            number: "4111111111111111".into(),
            cvv: "123".into(),
        },
    ];
    let encoded = cbor(&items);
    let got: Vec<vault_core::VaultItem> =
        ciborium::from_reader(&encoded[..]).expect("the known items must survive");
    assert_eq!(got.len(), 2);
    assert!(matches!(got[0], vault_core::VaultItem::SecureNote { .. }));
    assert!(matches!(got[1], vault_core::VaultItem::Unknown(_)));

    // And after this build saves, the future client still finds its own entry
    // intact — not silently deleted by the older machine in the fleet.
    let back: Vec<FutureVaultItem> = ciborium::from_reader(&cbor(&got)[..]).unwrap();
    assert_eq!(back, items);
}

#[test]
fn an_older_client_reading_a_bookmark() {
    let new = vault_core::VaultItem::Bookmark {
        title: "Sybr".into(),
        url: "https://sybr.no".into(),
        folder: "Arbeid".into(),
        notes: String::new(),
    };
    let mut buf = Vec::new();
    ciborium::into_writer(&new, &mut buf).unwrap();
    let got: Result<OldVaultItem, _> = ciborium::from_reader(&buf[..]);
    println!("OLD CLIENT / ONE BOOKMARK: {:?}", got.as_ref().err());
    assert!(got.is_err(), "if this passes, older clients are fine");
}

#[test]
fn and_a_whole_list_containing_one() {
    // The real shape: the vault decodes ALL items at once, so one unknown kind
    // decides the fate of every other entry in the file.
    let items = vec![
        vault_core::VaultItem::SecureNote {
            title: "Note".into(),
            body: "b".into(),
        },
        vault_core::VaultItem::Bookmark {
            title: "B".into(),
            url: "https://x.test".into(),
            folder: String::new(),
            notes: String::new(),
        },
    ];
    let mut buf = Vec::new();
    ciborium::into_writer(&items, &mut buf).unwrap();
    let got: Result<Vec<OldVaultItem>, _> = ciborium::from_reader(&buf[..]);
    println!("OLD CLIENT / LIST WITH ONE: {:?}", got.as_ref().err());
    assert!(
        got.is_err(),
        "one unknown kind takes the whole list with it"
    );
}

/// The end-to-end shape: a real vault, saved and reopened.
///
/// The serde round trip above proves the TYPE survives. This proves the FILE
/// does — that a machine running an older build can open the vault, use it,
/// save it, and hand it back with the newer machine's entries intact.
#[test]
fn a_vault_saved_by_this_build_keeps_what_it_could_not_read() {
    use vault_core::{KdfParams, Vault};

    // Cheap KDF: this test is about persistence, not password hashing.
    let params = KdfParams {
        algorithm: vault_core::KdfAlgorithm::Argon2id,
        m_cost_kib: 256,
        t_cost: 1,
        p_cost: 1,
        salt: vec![7u8; KdfParams::SALT_LEN],
    };

    let future_bytes = cbor(&FutureVaultItem::CreditCard {
        title: "Visa".into(),
        number: "4111111111111111".into(),
        cvv: "123".into(),
    });
    let unknown: vault_core::VaultItem = ciborium::from_reader(&future_bytes[..]).unwrap();

    let mut v = Vault::create("pw", params).unwrap();
    let id = uuid::Uuid::from_bytes([9u8; 16]);
    v.upsert_item(vault_core::Item {
        id,
        created_at: 0,
        modified_at: 1,
        deleted_at: None,
        revision: uuid::Uuid::nil(),
        revision_ancestors: Vec::new(),
        password_history: Vec::new(),
        sync_conflict: None,
        data: unknown,
    })
    .unwrap();

    // Save, close, reopen — the whole point.
    let bytes = v.to_bytes().unwrap();
    let mut reopened = Vault::from_bytes(&bytes).unwrap();
    reopened.unlock("pw").unwrap();

    assert_eq!(reopened.list_items(false).unwrap().len(), 1);
    let back = reopened.get_item(id).unwrap();
    let vault_core::VaultItem::Unknown(u) = &back.data else {
        panic!("the entry lost its identity: {:?}", back.data);
    };
    assert_eq!(u.kind, "CreditCard");

    // And the newer client still reads its own entry out of what we wrote.
    let recovered: FutureVaultItem = ciborium::from_reader(&u.raw[..]).unwrap();
    assert_eq!(
        recovered,
        FutureVaultItem::CreditCard {
            title: "Visa".into(),
            number: "4111111111111111".into(),
            cvv: "123".into(),
        }
    );
}
