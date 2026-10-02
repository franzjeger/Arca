//! Whoever can write the vault file — a sync provider, a stolen Drive token,
//! another local process — must not get past the container tag by relabelling
//! the file as an older, unauthenticated format. No password is needed for
//! any of these edits, so each one has to be refused on unlock.
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use vault_core::crypto::AeadBlob;
use vault_core::wire;
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

/// A current file's header, and the bytes after it (items and purges, whose
/// encoding every format shares). The format is positional, so the body reads
/// as any struct with its fields in order, and the tail encodes back to the
/// bytes it came from.
fn split(file: &[u8]) -> (VaultHeader, Vec<u8>) {
    #[derive(Deserialize)]
    struct Body {
        header: VaultHeader,
        items: Vec<(Uuid, AeadBlob)>,
        purges: Vec<(Uuid, i64)>,
    }
    let body: Body = wire::decode(&file[8..file.len() - AUTH_LEN], usize::MAX).unwrap();
    let rest = wire::encode(&(body.items, body.purges), usize::MAX).unwrap();
    (body.header, rest)
}

/// `header` in the layout V4 containers use, which ends at `rewrap_epoch`.
fn as_v4(header: &VaultHeader) -> Vec<u8> {
    #[derive(Serialize)]
    struct HeaderV4<'a> {
        format_version: u16,
        kdf: &'a KdfParams,
        master_wrapped_vault_key: &'a AeadBlob,
        device_wrapped_vault_key: &'a Option<AeadBlob>,
        rewrap_epoch: u64,
    }
    let v4 = HeaderV4 {
        format_version: 4,
        kdf: &header.kdf,
        master_wrapped_vault_key: &header.master_wrapped_vault_key,
        device_wrapped_vault_key: &header.device_wrapped_vault_key,
        rewrap_epoch: header.rewrap_epoch,
    };
    wire::encode(&v4, usize::MAX).unwrap()
}

fn opens(file: &[u8], password: &str) -> bool {
    Vault::from_bytes(file).is_ok_and(|mut vault| vault.unlock(password).is_ok())
}

#[test]
fn relabelling_as_v4_does_not_strip_the_tag() {
    let mut vault = Vault::create("pw", params()).unwrap();
    vault.upsert_item(login("bank")).unwrap();
    let file = vault.to_bytes().unwrap();
    assert!(opens(&file, "pw"));

    // What used to be enough: the magic and the header's version, two bytes.
    let mut two_bytes = file[..file.len() - AUTH_LEN].to_vec();
    two_bytes[7] = b'4';
    two_bytes[8] = 4;
    assert!(!opens(&two_bytes, "pw"));

    // The body re-encoded as a genuine V4 file would be.
    let (header, rest) = split(&file);
    let v4 = [b"SYBRVLT4".as_slice(), &as_v4(&header), &rest].concat();
    let mut relabelled = Vault::from_bytes(&v4).unwrap();
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

    let (old_header, _) = split(&before);
    let (_, new_rest) = split(&after);

    // Relabelled as V4, without a tag to check.
    let v4 = [b"SYBRVLT4".as_slice(), &as_v4(&old_header), &new_rest].concat();
    assert!(!opens(&v4, "leaked"));
    assert!(!opens(&v4, "changed"));

    // Kept current, with the current file's tag.
    let old_header = wire::encode(&old_header, usize::MAX).unwrap();
    let current = [
        &after[..8],
        &old_header,
        &new_rest,
        &after[after.len() - AUTH_LEN..],
    ]
    .concat();
    assert!(!opens(&current, "leaked"));

    let mut genuine = Vault::from_bytes(&after).unwrap();
    genuine.unlock("changed").unwrap();
    assert_eq!(genuine.list_items(false).unwrap().len(), 2);
}
