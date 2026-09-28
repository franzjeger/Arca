//! Whoever can write the vault file — a sync provider, a stolen Drive token,
//! another local process — must not get past the container tag by relabelling
//! the file as an older, unauthenticated format. No password is needed for
//! any of these edits, so each one has to be refused on unlock.
use bincode::Options;
use vault_core::{Item, KdfParams, Vault, VaultHeader, VaultItem};

const AUTH_LEN: usize = 32;

fn params() -> KdfParams {
    let mut p = KdfParams::new_default().unwrap();
    p.m_cost_kib = 256;
    p.t_cost = 1;
    p
}

fn login(title: &str) -> Item {
    Item::new(
        VaultItem::Login {
            title: title.into(),
            username: "me".into(),
            password: "secret".into(),
            url: "https://bank.example".into(),
            notes: String::new(),
            totp_secret: None,
        },
        1,
    )
}

fn header_len(file: &[u8]) -> usize {
    let codec = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes();
    let header: VaultHeader = codec.deserialize(&file[8..]).unwrap();
    codec.serialized_size(&header).unwrap() as usize
}

#[test]
fn two_bytes_do_not_strip_the_tag() {
    let mut vault = Vault::create("pw", params()).unwrap();
    vault.upsert_item(login("bank")).unwrap();
    let mut file = vault.to_bytes().unwrap();

    file.truncate(file.len() - AUTH_LEN);
    file[7] = b'4'; // SYBRVLT6 -> SYBRVLT4
    file[8] = 4; // header.format_version -> 4

    let mut relabelled = Vault::from_bytes(&file).unwrap();
    assert!(relabelled.unlock("pw").is_err());
}

#[test]
fn an_old_header_cannot_bring_back_an_old_password() {
    let mut vault = Vault::create("leaked", params()).unwrap();
    vault.upsert_item(login("bank")).unwrap();
    let before = vault.to_bytes().unwrap();
    vault.change_master_password("changed").unwrap();
    vault.upsert_item(login("added after the change")).unwrap();
    let after = vault.to_bytes().unwrap();

    let (old_len, new_len) = (header_len(&before), header_len(&after));
    assert_eq!(old_len, new_len);
    let old_header = &before[8..8 + old_len];
    let new_body = &after[8 + new_len..after.len() - AUTH_LEN];

    // Relabelled as V4, without a tag to check.
    let mut v4 = [b"SYBRVLT4".as_slice(), old_header, new_body].concat();
    v4[8] = 4;
    let mut spliced = Vault::from_bytes(&v4).unwrap();
    assert!(spliced.unlock("leaked").is_err());
    assert!(spliced.unlock("changed").is_err());

    // Kept as V6, with the current file's tag.
    let v6 = [
        &after[..8],
        old_header,
        new_body,
        &after[after.len() - AUTH_LEN..],
    ]
    .concat();
    let mut spliced = Vault::from_bytes(&v6).unwrap();
    assert!(spliced.unlock("leaked").is_err());

    let mut genuine = Vault::from_bytes(&after).unwrap();
    genuine.unlock("changed").unwrap();
    assert_eq!(genuine.list_items(false).unwrap().len(), 2);
}
