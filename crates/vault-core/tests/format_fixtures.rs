//! Vault files Arca has already written must open with every later build.
//!
//! Every other test makes its vault with the code under test, so a change that
//! stops yesterday's files from opening (a new crypto crate, a serialization
//! tweak) passes all of them. These two files were written by released code
//! and are never regenerated:
//!
//! - `fixtures/v5-from-0.6.2.vault` by the 0.6.2 source (commit ba7254d), the
//!   format real vaults had before 0.7.0;
//! - `fixtures/v7-from-0.7.0.vault` by 0.7.0, after a master password change,
//!   with a device key and a device in the sealed device list.
//!
//! Both hold the same fixed contents, and what those yield never changes,
//! down to the bytes of the signatures the stored keys make.

use vault_core::{passkey, ssh, Item, SymmetricKey, Vault, VaultItem};

const V5: &[u8] = include_bytes!("fixtures/v5-from-0.6.2.vault");
const V7: &[u8] = include_bytes!("fixtures/v7-from-0.7.0.vault");

const FIRST_PASSWORD: &str = "correct horse battery staple";
const CHANGED_PASSWORD: &str = "new horse battery staple";
const DEVICE_KEY: [u8; 32] = [5; 32];

/// What 0.6.2 and 0.7.0 both signed with the stored SSH key (Ed25519) and
/// passkey (ES256, RFC 6979), over fixed messages.
const SSH_SIGNATURE: &str = "0000000b7373682d65643235353139000000406fc3562865b878f96180fb971b33005ae2d811a1358c0153e969461ebadd9b0224d4c208dee096c12416070823addde2ef4681ee7ef4803169055819ef84970a";
const PASSKEY_AUTH_DATA: &str =
    "9b263fbcb589853137b33ddcafa5bcc5403464ead4da766d0f819348bf8d472c1d00000000";
const PASSKEY_SIGNATURE: &str = "3046022100f286e5b9cc1ac9ade08dc3ffe604fb36f3805552acd2d1db4e231370cd770a3e022100d9b4315ff5191c44b6bdd4c74178276695f189da964b03d0e7970400af94d116";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn item<'a>(items: &'a [&Item], title: &str) -> &'a VaultItem {
    &items
        .iter()
        .find(|i| i.data.title() == title)
        .unwrap_or_else(|| panic!("no item {title:?}"))
        .data
}

/// The fixed contents both files were written with. Returns the stored SSH
/// seed and passkey scalar, for the signatures.
fn assert_contents(vault: &Vault) -> (Vec<u8>, Vec<u8>) {
    let items: Vec<&Item> = vault.active_items().unwrap().collect();
    assert_eq!(items.len(), 5);

    let VaultItem::Login {
        username,
        password,
        url,
        totp_secret,
        notes,
        ..
    } = item(&items, "Example")
    else {
        panic!("Example is not a login")
    };
    assert_eq!(
        (username.as_str(), password.as_str(), url.as_str()),
        (
            "alice@example.test",
            "hunter2-correct-horse",
            "https://example.test/login"
        )
    );
    assert_eq!(totp_secret.as_deref(), Some("JBSWY3DPEHPK3PXP"));
    assert_eq!(notes, "fixture note");

    let VaultItem::SecureNote { body, .. } = item(&items, "Recovery codes") else {
        panic!("Recovery codes is not a note")
    };
    assert_eq!(body, "1111-2222\n3333-4444");

    let VaultItem::Wifi {
        ssid,
        password,
        security,
        hidden,
        ..
    } = item(&items, "Home")
    else {
        panic!("Home is not a Wi-Fi network")
    };
    assert_eq!(
        (ssid.as_str(), password.as_str(), security.as_str(), *hidden),
        ("ArcaTest", "wifi-password", "WPA2", false)
    );

    let VaultItem::SshKey {
        public_key,
        private_key: seed,
        fingerprint,
        comment,
        ..
    } = item(&items, "fixture@arca")
    else {
        panic!("fixture@arca is not an SSH key")
    };
    assert_eq!(comment, "fixture@arca");
    assert_eq!(public_key, &ssh::public_blob(seed).unwrap());
    assert_eq!(fingerprint, &ssh::fingerprint(public_key));

    let VaultItem::Passkey {
        rp_id,
        user_name,
        user_handle,
        credential_id,
        private_key: scalar,
        ..
    } = item(&items, "example.test")
    else {
        panic!("example.test is not a passkey")
    };
    assert_eq!(
        (rp_id.as_str(), user_name.as_str()),
        ("example.test", "alice")
    );
    assert_eq!(user_handle, b"alice-handle");
    assert_eq!(credential_id, &[1u8; 16]);

    (seed.clone(), scalar.clone())
}

#[test]
fn a_vault_written_by_0_6_2_opens_and_is_rewritten_as_the_current_format() {
    let mut vault = Vault::from_bytes(V5).unwrap();
    assert_eq!(vault.header().format_version, 5);
    assert!(vault.unlock("not the password").is_err());
    vault.unlock(FIRST_PASSWORD).unwrap();
    assert_contents(&vault);

    // Its quick-unlock key still opens it: a V5 file is authenticated.
    let mut quick = Vault::from_bytes(V5).unwrap();
    quick
        .unlock_with_device_key(&SymmetricKey::from_bytes(DEVICE_KEY))
        .unwrap();
    assert_contents(&quick);

    let rewritten = vault.to_bytes().unwrap();
    let mut again = Vault::from_bytes(&rewritten).unwrap();
    assert!(again.header().format_version > 5);
    again.unlock(FIRST_PASSWORD).unwrap();
    assert_contents(&again);
}

#[test]
fn a_vault_written_by_0_7_0_opens_with_its_changed_password_and_device_key() {
    let mut vault = Vault::from_bytes(V7).unwrap();
    assert_eq!(vault.header().format_version, 7);
    assert_eq!(vault.header().key_epoch, 1);
    assert!(vault.unlock(FIRST_PASSWORD).is_err());
    vault.unlock(CHANGED_PASSWORD).unwrap();
    assert_contents(&vault);
    let devices = vault.devices().unwrap();
    assert_eq!(devices.len(), 1);
    assert_eq!(
        (devices[0].name.as_str(), devices[0].uploads),
        ("Fixture Mac", 1)
    );

    let mut quick = Vault::from_bytes(V7).unwrap();
    quick
        .unlock_with_device_key(&SymmetricKey::from_bytes(DEVICE_KEY))
        .unwrap();
    assert_contents(&quick);
}

#[test]
fn keys_stored_by_either_version_sign_as_they_always_have() {
    for (bytes, password) in [(V5, FIRST_PASSWORD), (V7, CHANGED_PASSWORD)] {
        let mut vault = Vault::from_bytes(bytes).unwrap();
        vault.unlock(password).unwrap();
        let (seed, scalar) = assert_contents(&vault);

        let signature = ssh::sign(&seed, b"arca format fixture").unwrap();
        assert_eq!(hex(&signature), SSH_SIGNATURE);
        let (auth_data, signature) =
            passkey::assert(&scalar, "example.test", &[2u8; 32], true).unwrap();
        assert_eq!(hex(&auth_data), PASSKEY_AUTH_DATA);
        assert_eq!(hex(&signature), PASSKEY_SIGNATURE);
    }
}
