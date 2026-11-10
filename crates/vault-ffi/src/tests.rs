#![allow(clippy::too_many_lines)]

use super::*;
use std::ffi::CString;
use std::ptr;

/// Drive create → assert entirely through the C ABI and verify the
/// signature with vault-core, exercising the exact bytes Swift will get.
#[test]
fn ffi_create_then_assert_round_trips() {
    assert_eq!(vault_ffi_abi_version(), ABI_VERSION);
    let rp = CString::new("github.com").unwrap();

    let (mut cid, mut cid_len) = (ptr::null_mut(), 0usize);
    let (mut pk, mut pk_len) = (ptr::null_mut(), 0usize);
    let (mut att, mut att_len) = (ptr::null_mut(), 0usize);
    let rc = unsafe {
        vault_ffi_passkey_create(
            rp.as_ptr(),
            true,
            &mut cid,
            &mut cid_len,
            &mut pk,
            &mut pk_len,
            &mut att,
            &mut att_len,
        )
    };
    assert_eq!(rc, OK);
    assert_eq!(pk_len, 32);
    assert!(cid_len == 16 && att_len > 0);

    let private_key = unsafe { slice::from_raw_parts(pk, pk_len).to_vec() };
    let hash = [7u8; 32];
    let (mut ad, mut ad_len) = (ptr::null_mut(), 0usize);
    let (mut sig, mut sig_len) = (ptr::null_mut(), 0usize);
    let rc = unsafe {
        vault_ffi_passkey_assert(
            private_key.as_ptr(),
            private_key.len(),
            rp.as_ptr(),
            true,
            hash.as_ptr(),
            hash.len(),
            &mut ad,
            &mut ad_len,
            &mut sig,
            &mut sig_len,
        )
    };
    assert_eq!(rc, OK);

    // The signature the FFI produced verifies against the credential.
    let auth_data = unsafe { slice::from_raw_parts(ad, ad_len).to_vec() };
    let signature = unsafe { slice::from_raw_parts(sig, sig_len).to_vec() };
    let mut signed = auth_data;
    signed.extend_from_slice(&hash);
    use p256_check::verify;
    assert!(verify(&private_key, &signed, &signature));

    unsafe {
        vault_ffi_free(cid, cid_len);
        vault_ffi_free(pk, pk_len);
        vault_ffi_free(att, att_len);
        vault_ffi_free(ad, ad_len);
        vault_ffi_free(sig, sig_len);
    }
}

/// The phone's whole passkey story over the ABI: enumerate what the vault
/// holds, assert with nothing but an item id, and check the signature
/// against the credential's own key.
///
/// Verifying the signature is the part that matters. A test that only
/// checks OK-codes would pass with an assert wired to the wrong item's
/// key, and that failure reaches the user as "GitHub rejected your
/// passkey" with no path back to here.
#[test]
fn passkey_identities_and_assert_by_id_round_trip() {
    // A real credential, minted by the same core the desktop uses.
    let rp = CString::new("github.com").unwrap();
    let (mut cid, mut cid_len) = (ptr::null_mut(), 0usize);
    let (mut pk, mut pk_len) = (ptr::null_mut(), 0usize);
    let (mut att, mut att_len) = (ptr::null_mut(), 0usize);
    assert_eq!(
        unsafe {
            vault_ffi_passkey_create(
                rp.as_ptr(),
                true,
                &mut cid,
                &mut cid_len,
                &mut pk,
                &mut pk_len,
                &mut att,
                &mut att_len,
            )
        },
        OK
    );
    let credential_id = unsafe { slice::from_raw_parts(cid, cid_len).to_vec() };
    let private_key = unsafe { slice::from_raw_parts(pk, pk_len).to_vec() };
    unsafe {
        vault_ffi_free(cid, cid_len);
        vault_ffi_free(pk, pk_len);
        vault_ffi_free(att, att_len);
    }

    // Into a vault, out through file bytes, back in via the ABI — the same
    // road a synced credential travels to reach the phone.
    use vault_core::{Item, KdfAlgorithm, KdfParams};
    let params = KdfParams {
        algorithm: KdfAlgorithm::Argon2id,
        m_cost_kib: 256,
        t_cost: 1,
        p_cost: 1,
        salt: vec![7u8; KdfParams::SALT_LEN],
    };
    let mut vault = Vault::create("pw", params).unwrap();
    let item = Item::new(
        VaultItem::Passkey {
            title: "GitHub".into(),
            rp_id: "github.com".into(),
            user_name: "frank".into(),
            user_handle: vec![9, 9, 9],
            credential_id: credential_id.clone(),
            private_key: private_key.clone(),
            sign_count: 0,
        },
        0,
    );
    let item_id = item.id.to_string();
    vault.upsert_item(item).unwrap();
    let bytes = vault.to_bytes().unwrap();

    let mut handle: *mut VaultHandle = ptr::null_mut();
    let pw = CString::new("pw").unwrap();
    assert_eq!(
        unsafe {
            vault_ffi_vault_open_password(bytes.as_ptr(), bytes.len(), pw.as_ptr(), &mut handle)
        },
        OK
    );

    // Enumeration carries what the credential store needs — and no more.
    let (mut out, mut len) = (ptr::null_mut(), 0usize);
    assert_eq!(
        unsafe { vault_ffi_passkey_identities(handle, &mut out, &mut len) },
        OK
    );
    let rows: serde_json::Value =
        serde_json::from_slice(unsafe { slice::from_raw_parts(out, len) }).unwrap();
    unsafe { vault_ffi_free(out, len) };
    let rows = rows.as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["rp_id"], "github.com");
    assert_eq!(rows[0]["id"], item_id.as_str());
    let b64 = data_encoding::BASE64;
    assert_eq!(
        b64.decode(rows[0]["credential_id"].as_str().unwrap().as_bytes())
            .unwrap(),
        credential_id
    );
    assert!(
        rows[0].get("private_key").is_none(),
        "the private key must never cross"
    );

    // Assert by id: the key stays behind the handle.
    let hash = [7u8; 32];
    let id_c = CString::new(item_id).unwrap();
    let (mut out, mut len) = (ptr::null_mut(), 0usize);
    assert_eq!(
        unsafe {
            vault_ffi_passkey_assert_for_id(
                handle,
                id_c.as_ptr(),
                hash.as_ptr(),
                hash.len(),
                1,
                &mut out,
                &mut len,
            )
        },
        OK
    );
    let resp: serde_json::Value =
        serde_json::from_slice(unsafe { slice::from_raw_parts(out, len) }).unwrap();
    unsafe { vault_ffi_free(out, len) };

    assert_eq!(
        b64.decode(resp["user_handle"].as_str().unwrap().as_bytes())
            .unwrap(),
        vec![9, 9, 9]
    );
    // WebAuthn signs authenticatorData || clientDataHash. Verified against
    // the credential's own key, not merely "a signature came back".
    let auth_data = b64
        .decode(resp["authenticator_data"].as_str().unwrap().as_bytes())
        .unwrap();
    let signature = b64
        .decode(resp["signature"].as_str().unwrap().as_bytes())
        .unwrap();
    let mut signed = auth_data;
    signed.extend_from_slice(&hash);
    use p256_check::verify;
    assert!(
        verify(&private_key, &signed, &signature),
        "assertion did not verify against the credential's key"
    );

    // An unknown id is a clean not-found, not a panic.
    let bogus = CString::new(uuid::Uuid::new_v4().to_string()).unwrap();
    let (mut out, mut len) = (ptr::null_mut(), 0usize);
    assert_eq!(
        unsafe {
            vault_ffi_passkey_assert_for_id(
                handle,
                bogus.as_ptr(),
                hash.as_ptr(),
                hash.len(),
                1,
                &mut out,
                &mut len,
            )
        },
        ERR_NOT_FOUND
    );
    unsafe { vault_ffi_vault_free(handle) };
}

#[test]
fn null_and_bad_utf8_are_errors_not_crashes() {
    let mut a = ptr::null_mut();
    let mut al = 0usize;
    // Null rp_id -> UTF8/null error, no panic.
    let rc = unsafe {
        vault_ffi_passkey_create(
            ptr::null(),
            true,
            &mut a,
            &mut al,
            &mut a,
            &mut al,
            &mut a,
            &mut al,
        )
    };
    assert!(rc < 0);
    // Freeing null is a no-op.
    unsafe { vault_ffi_free(ptr::null_mut(), 0) };
}

// ---- passwords surface (ABI v2) -------------------------------------

/// A serialized device-unlock vault holding one login, plus the raw device
/// key and the login's id string.
fn sample_vault() -> (Vec<u8>, [u8; KEY_LEN], String) {
    use vault_core::{Item, KdfAlgorithm, KdfParams};
    let params = KdfParams {
        algorithm: KdfAlgorithm::Argon2id,
        m_cost_kib: 256,
        t_cost: 1,
        p_cost: 1,
        salt: vec![7u8; KdfParams::SALT_LEN],
    };
    let mut v = Vault::create("pw", params).unwrap();
    let device = SymmetricKey::generate().unwrap();
    v.enable_device_unlock(&device).unwrap();
    let item = Item::new(
        VaultItem::Login {
            title: "GitHub".into(),
            username: "alice@example.test".into(),
            password: "s3cr3t-pw".into(),
            url: "https://github.com/login".into(),
            totp_secret: None,
            notes: String::new(),
        },
        0,
    );
    let id = item.id.to_string();
    v.upsert_item(item).unwrap();
    (v.to_bytes().unwrap(), *device.as_bytes(), id)
}

#[test]
fn history_ffi_exposes_metadata_and_prepares_restore_without_mutating_live_handle() {
    let (bytes, key, id) = sample_vault();
    let handle = open_handle(&bytes, &key);
    let id_c = std::ffi::CString::new(id.clone()).unwrap();
    {
        let mut vault = unsafe { &*handle }.vault.lock().unwrap();
        let mut item = vault.get_item(uuid::Uuid::parse_str(&id).unwrap()).unwrap();
        if let VaultItem::Login { password, .. } = &mut item.data {
            *password = "replacement".into();
        }
        item.modified_at = 2;
        vault.upsert_item(item).unwrap();
    }
    let metadata = json_call_id(handle, id_c.as_ptr(), vault_ffi_password_history);
    assert!(!metadata.contains("s3cr3t-pw"));
    let metadata: serde_json::Value = serde_json::from_str(&metadata).unwrap();
    let revision = std::ffi::CString::new(metadata[0]["id"].as_str().unwrap()).unwrap();
    let (mut out, mut len) = (ptr::null_mut(), 0);
    unsafe {
        assert_eq!(
            vault_ffi_history_password(
                handle,
                id_c.as_ptr(),
                revision.as_ptr(),
                &mut out,
                &mut len
            ),
            OK
        );
        assert_eq!(slice::from_raw_parts(out, len), b"s3cr3t-pw");
        vault_ffi_free(out, len);
        assert_eq!(
            vault_ffi_restore_password_history(
                handle,
                id_c.as_ptr(),
                revision.as_ptr(),
                3,
                &mut out,
                &mut len
            ),
            OK
        );
        let mut restored = Vault::from_bytes(slice::from_raw_parts(out, len)).unwrap();
        restored.unlock("pw").unwrap();
        assert_eq!(
            restored
                .get_item(uuid::Uuid::parse_str(&id).unwrap())
                .unwrap()
                .password(),
            Some("s3cr3t-pw")
        );
        vault_ffi_free(out, len);
        assert_eq!(
            (*handle)
                .vault
                .lock()
                .unwrap()
                .get_item(uuid::Uuid::parse_str(&id).unwrap())
                .unwrap()
                .password(),
            Some("replacement")
        );
        assert_eq!(
            vault_ffi_password_history(ptr::null_mut(), id_c.as_ptr(), &mut out, &mut len),
            ERR_NULL_ARG
        );
        vault_ffi_vault_free(handle);
    }
}

// Pinned deliberately: clients gate features on this number, so a bump has
// to be a conscious edit here, not a side effect.
#[test]
fn abi_version_is_22() {
    assert_eq!(vault_ffi_abi_version(), 22);
}

/// A phone that kept the copy sealed after a password change takes the
/// change on from it with the new password alone: locked, offline, and
/// only once.
#[test]
fn a_kept_copy_takes_a_changed_password_on() {
    let mut params = vault_core::KdfParams::new_default().unwrap();
    params.m_cost_kib = 256;
    params.t_cost = 1;
    let here = Vault::create("old", params).unwrap();
    let local = here.to_bytes().unwrap();
    let mut elsewhere = Vault::from_bytes(&local).unwrap();
    elsewhere.unlock("old").unwrap();
    elsewhere.change_master_password("new").unwrap();
    let changed = elsewhere.to_bytes().unwrap();

    let epoch = |bytes: &[u8]| {
        let mut epoch = u64::MAX;
        let code = unsafe { vault_ffi_vault_key_epoch(bytes.as_ptr(), bytes.len(), &mut epoch) };
        assert_eq!(code, OK);
        epoch
    };
    assert_eq!((epoch(&local), epoch(&changed)), (0, 1));

    let mut handle: *mut VaultHandle = ptr::null_mut();
    let loaded = unsafe { vault_ffi_vault_load(local.as_ptr(), local.len(), &mut handle) };
    assert_eq!(loaded, OK);
    let adopt = |password: &str| {
        let password = CString::new(password).unwrap();
        unsafe { vault_ffi_vault_adopt(handle, changed.as_ptr(), changed.len(), password.as_ptr()) }
    };
    assert_eq!(adopt("old"), ERR_DECRYPT);
    assert_eq!(adopt("new"), OK);
    let (mut out, mut len) = (ptr::null_mut(), 0usize);
    assert_eq!(unsafe { vault_ffi_items(handle, &mut out, &mut len) }, OK);
    unsafe { vault_ffi_free(out, len) };
    assert_eq!(adopt("new"), ERR_NOT_FOUND);

    let merged =
        unsafe { vault_ffi_merge_and_serialize(handle, ptr::null(), 0, &mut out, &mut len) };
    assert_eq!(merged, OK);
    let written = unsafe { std::slice::from_raw_parts(out, len) }.to_vec();
    unsafe { vault_ffi_free(out, len) };
    unsafe { vault_ffi_vault_free(handle) };
    assert_eq!(epoch(&written), 1);
    let mut reopened = Vault::from_bytes(&written).unwrap();
    assert!(reopened.unlock("old").is_err());
    reopened.unlock("new").unwrap();
}

/// A loaded handle is a vault not yet open: it answers what the header
/// says, and every read of the items is refused until something opens it.
#[test]
fn a_loaded_vault_reads_nothing_until_it_is_opened() {
    let mut params = vault_core::KdfParams::new_default().unwrap();
    params.m_cost_kib = 256;
    params.t_cost = 1;
    let mut vault = Vault::create("pw", params).unwrap();
    vault
        .enable_device_unlock(&SymmetricKey::generate().unwrap())
        .unwrap();
    let bytes = vault.to_bytes().unwrap();

    let mut handle: *mut VaultHandle = ptr::null_mut();
    let loaded = unsafe { vault_ffi_vault_load(bytes.as_ptr(), bytes.len(), &mut handle) };
    assert_eq!(loaded, OK);
    assert_eq!(unsafe { vault_ffi_has_device_unlock(handle) }, 1);
    let (mut out, mut len) = (ptr::null_mut(), 0usize);
    assert_eq!(
        unsafe { vault_ffi_items(handle, &mut out, &mut len) },
        ERR_LOCKED
    );
    assert_eq!(
        unsafe { vault_ffi_identities(handle, &mut out, &mut len) },
        ERR_LOCKED
    );
    let merged =
        unsafe { vault_ffi_merge_and_serialize(handle, ptr::null(), 0, &mut out, &mut len) };
    assert_eq!(merged, ERR_LOCKED);
    assert!(out.is_null());
    unsafe { vault_ffi_vault_free(handle) };

    let not_a_vault = b"not a vault";
    let refused =
        unsafe { vault_ffi_vault_load(not_a_vault.as_ptr(), not_a_vault.len(), &mut handle) };
    assert_ne!(refused, OK);
    assert!(handle.is_null());
}

// ---- duplicates (ABI v22) ----------------------------------------------

/// Two logins for one account, and two different accounts that share only
/// a username and have no site.
fn duplicates_vault() -> (Vec<u8>, [u8; KEY_LEN]) {
    use vault_core::{Item, KdfAlgorithm, KdfParams};
    let params = KdfParams {
        algorithm: KdfAlgorithm::Argon2id,
        m_cost_kib: 256,
        t_cost: 1,
        p_cost: 1,
        salt: vec![7u8; KdfParams::SALT_LEN],
    };
    let mut v = Vault::create("pw", params).unwrap();
    let device = SymmetricKey::generate().unwrap();
    v.enable_device_unlock(&device).unwrap();
    for (title, username, url, password, modified) in [
        (
            "Site",
            "me@example.test",
            "https://example.test",
            "older-pw",
            10,
        ),
        (
            "Site",
            "me@example.test",
            "https://example.test/login",
            "newer-pw",
            20,
        ),
        ("Router", "admin", "", "router-pw", 30),
        ("NAS", "admin", "", "nas-pw", 40),
    ] {
        let data = VaultItem::Login {
            title: title.into(),
            username: username.into(),
            password: password.into(),
            url: url.into(),
            totp_secret: None,
            notes: String::new(),
        };
        v.upsert_item(Item::new(data, modified)).unwrap();
    }
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(device.as_bytes());
    (v.to_bytes().unwrap(), key)
}

fn merge_call(handle: *mut VaultHandle, request: &str) -> (i32, usize, Vec<u8>) {
    let (mut out, mut len, mut merged) = (ptr::null_mut(), 0usize, 0usize);
    let code = unsafe {
        vault_ffi_merge_duplicates(
            handle,
            request.as_ptr(),
            request.len(),
            100,
            &mut merged,
            &mut out,
            &mut len,
        )
    };
    let bytes = if out.is_null() {
        Vec::new()
    } else {
        let bytes = unsafe { slice::from_raw_parts(out, len) }.to_vec();
        unsafe { vault_ffi_free(out, len) };
        bytes
    };
    (code, merged, bytes)
}

/// What the review showed, as a request that merges its one group.
fn merge_all(review: &serde_json::Value) -> serde_json::Value {
    let group = &review[0];
    let logins = group["logins"].as_array().unwrap();
    serde_json::json!({
        "choices": [{
            "keep": group["keep"],
            "ids": logins.iter().map(|l| l["id"].clone()).collect::<Vec<_>>(),
        }],
        "shown": logins
            .iter()
            .map(|l| serde_json::json!({ "id": l["id"], "revision": l["revision"] }))
            .collect::<Vec<_>>(),
    })
}

#[test]
fn duplicates_are_reviewed_then_merged_through_the_c_abi() {
    let (bytes, key) = duplicates_vault();
    let handle = open_handle(&bytes, &key);

    let json = json_call(handle, vault_ffi_find_duplicates);
    assert!(
        !json.contains("-pw"),
        "the review carries no password: {json}"
    );
    let review: serde_json::Value = serde_json::from_str(&json).unwrap();
    // One group: Router and NAS are two accounts, not one.
    assert_eq!(review.as_array().unwrap().len(), 1);
    assert_eq!(review[0]["possible"], false);
    assert_eq!(review[0]["logins"][0]["title"], "Site");
    assert_eq!(review[0]["logins"][0]["modifiedAt"], 20);

    let (code, merged, out) = merge_call(handle, &merge_all(&review).to_string());
    assert_eq!((code, merged), (OK, 1));
    // The handle and the bytes it gave agree: nothing left to merge.
    assert_eq!(json_call(handle, vault_ffi_find_duplicates), "[]");
    let reopened = open_handle(&out, &key);
    assert_eq!(json_call(reopened, vault_ffi_find_duplicates), "[]");
    let kept: serde_json::Value =
        serde_json::from_str(&json_call(reopened, vault_ffi_items)).unwrap();
    assert_eq!(kept.as_array().unwrap().len(), 3);
    unsafe {
        vault_ffi_vault_free(reopened);
        vault_ffi_vault_free(handle);
    }
}

#[test]
fn a_merge_about_logins_that_changed_is_refused_and_changes_nothing() {
    let (bytes, key) = duplicates_vault();
    let handle = open_handle(&bytes, &key);
    let review: serde_json::Value =
        serde_json::from_str(&json_call(handle, vault_ffi_find_duplicates)).unwrap();

    // A login shown with a revision it no longer has: synced in between.
    let mut request = merge_all(&review);
    request["shown"][0]["revision"] = serde_json::json!(uuid::Uuid::new_v4());
    let (code, merged, out) = merge_call(handle, &request.to_string());
    assert_eq!((code, merged, out.len()), (ERR_CHANGED, 0, 0));
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&json_call(handle, vault_ffi_find_duplicates))
            .unwrap(),
        review
    );

    // Not the shape asked for, and not JSON at all.
    let (code, ..) = merge_call(handle, r#"{"choices":[]}"#);
    assert_eq!(code, ERR_OP_FAILED);
    let (code, ..) = merge_call(handle, "merge everything");
    assert_eq!(code, ERR_OP_FAILED);
    unsafe { vault_ffi_vault_free(handle) };

    // A vault that is only loaded, not opened, shows nothing.
    let mut locked: *mut VaultHandle = ptr::null_mut();
    assert_eq!(
        unsafe { vault_ffi_vault_load(bytes.as_ptr(), bytes.len(), &mut locked) },
        OK
    );
    let (mut out, mut len) = (ptr::null_mut(), 0usize);
    assert_eq!(
        unsafe { vault_ffi_find_duplicates(locked, &mut out, &mut len) },
        ERR_LOCKED
    );
    assert_eq!(
        unsafe { vault_ffi_find_duplicates(ptr::null_mut(), &mut out, &mut len) },
        ERR_NULL_ARG
    );
    unsafe { vault_ffi_vault_free(locked) };
}

// ---- every-kind surface (ABI v7) -------------------------------------

/// Open a handle with the device key, or fail the test loudly.
fn open_handle(bytes: &[u8], key: &[u8; KEY_LEN]) -> *mut VaultHandle {
    let mut handle: *mut VaultHandle = ptr::null_mut();
    assert_eq!(
        unsafe {
            vault_ffi_vault_open(
                bytes.as_ptr(),
                bytes.len(),
                key.as_ptr(),
                KEY_LEN,
                &mut handle,
            )
        },
        OK
    );
    handle
}

/// Call a `(handle, **out, *len)` export and take the JSON as a String,
/// freeing the buffer the way a real caller must.
fn json_call(
    handle: *mut VaultHandle,
    f: unsafe extern "C" fn(*mut VaultHandle, *mut *mut u8, *mut usize) -> i32,
) -> String {
    let (mut out, mut len) = (ptr::null_mut(), 0usize);
    assert_eq!(unsafe { f(handle, &mut out, &mut len) }, OK);
    let s = unsafe { std::str::from_utf8(slice::from_raw_parts(out, len)).unwrap() }.to_string();
    unsafe { vault_ffi_free(out, len) };
    s
}

/// Same, for the exports that take an id.
fn json_call_id(
    handle: *mut VaultHandle,
    id: *const c_char,
    f: unsafe extern "C" fn(*mut VaultHandle, *const c_char, *mut *mut u8, *mut usize) -> i32,
) -> String {
    let (mut out, mut len) = (ptr::null_mut(), 0usize);
    assert_eq!(unsafe { f(handle, id, &mut out, &mut len) }, OK);
    let s = unsafe { std::str::from_utf8(slice::from_raw_parts(out, len)).unwrap() }.to_string();
    unsafe { vault_ffi_free(out, len) };
    s
}

/// A vault holding one of EVERY kind, which is the case that matters: for
/// six ABI versions `identities` filtered to logins, so four kinds were
/// invisible to any caller that had no other way to ask.
fn every_kind_vault() -> (Vec<u8>, [u8; KEY_LEN]) {
    use vault_core::{Item, KdfAlgorithm, KdfParams};
    let params = KdfParams {
        algorithm: KdfAlgorithm::Argon2id,
        m_cost_kib: 256,
        t_cost: 1,
        p_cost: 1,
        salt: vec![7u8; KdfParams::SALT_LEN],
    };
    let mut v = Vault::create("pw", params).unwrap();
    let device = SymmetricKey::generate().unwrap();
    v.enable_device_unlock(&device).unwrap();
    for data in [
        VaultItem::Login {
            title: "GitHub".into(),
            username: "alice@example.test".into(),
            password: "pw".into(),
            url: "https://github.com".into(),
            // RFC 4648 base32, so `current_totp` has something real to chew.
            totp_secret: Some("JBSWY3DPEHPK3PXP".into()),
            notes: String::new(),
        },
        VaultItem::Wifi {
            title: "Home".into(),
            ssid: "Sybr".into(),
            password: "wifi-pw".into(),
            security: "WPA2".into(),
            hidden: false,
            notes: String::new(),
        },
        VaultItem::SecureNote {
            title: "Recovery".into(),
            body: "the body".into(),
        },
    ] {
        v.upsert_item(Item::new(data, 0)).unwrap();
    }
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(device.as_bytes());
    (v.to_bytes().unwrap(), key)
}

/// The bug this ABI version exists to fix.
#[test]
fn items_returns_every_kind_while_identities_stays_logins_only() {
    let (bytes, key) = every_kind_vault();
    let handle = open_handle(&bytes, &key);

    let all: serde_json::Value = serde_json::from_str(&json_call(handle, vault_ffi_items)).unwrap();
    let kinds: Vec<&str> = all
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["kind"].as_str().unwrap())
        .collect();
    assert_eq!(kinds.len(), 3, "every kind should be listed");
    assert!(kinds.contains(&"wifi"));
    assert!(kinds.contains(&"secure_note"));

    // And the credential-store feed must NOT have widened: a Wi-Fi password
    // in the QuickType bar is nonsense, and AutoFill depends on this.
    let ids: serde_json::Value =
        serde_json::from_str(&json_call(handle, vault_ffi_identities)).unwrap();
    assert_eq!(
        ids.as_array().unwrap().len(),
        1,
        "identities stays logins-only"
    );

    unsafe { vault_ffi_vault_free(handle) };
}

#[test]
fn detail_carries_each_kinds_own_fields_and_no_ssh_private_key() {
    let (bytes, key) = every_kind_vault();
    let handle = open_handle(&bytes, &key);
    let all: serde_json::Value = serde_json::from_str(&json_call(handle, vault_ffi_items)).unwrap();

    for item in all.as_array().unwrap() {
        let id = std::ffi::CString::new(item["id"].as_str().unwrap()).unwrap();
        let detail: serde_json::Value =
            serde_json::from_str(&json_call_id(handle, id.as_ptr(), vault_ffi_item_detail))
                .unwrap();
        assert_eq!(detail["kind"], item["kind"]);
        match detail["kind"].as_str().unwrap() {
            "wifi" => assert_eq!(detail["password"], "wifi-pw"),
            "secure_note" => assert_eq!(detail["body"], "the body"),
            "login" => {
                assert_eq!(detail["password"], "pw");
                // The TOTP SECRET must never appear — only the flag.
                assert_eq!(detail["has_totp"], true);
                assert!(detail.get("totp_secret").is_none());
            }
            other => panic!("unexpected kind {other}"),
        }
    }
    unsafe { vault_ffi_vault_free(handle) };
}

#[test]
fn totp_returns_a_live_code_and_refuses_items_without_one() {
    let (bytes, key) = every_kind_vault();
    let handle = open_handle(&bytes, &key);
    let all: serde_json::Value = serde_json::from_str(&json_call(handle, vault_ffi_items)).unwrap();

    for item in all.as_array().unwrap() {
        let id = std::ffi::CString::new(item["id"].as_str().unwrap()).unwrap();
        let mut out: *mut u8 = std::ptr::null_mut();
        let mut len: usize = 0;
        let rc = unsafe { vault_ffi_totp(handle, id.as_ptr(), &mut out, &mut len) };
        if item["kind"] == "login" {
            assert_eq!(rc, OK);
            let json: serde_json::Value = serde_json::from_str(&unsafe {
                String::from_utf8_lossy(std::slice::from_raw_parts(out, len)).into_owned()
            })
            .unwrap();
            assert_eq!(json["code"].as_str().unwrap().len(), 6);
            assert_eq!(json["period"], 30);
            unsafe { vault_ffi_free(out, len) };
        } else {
            // Not "empty code" — an item with no TOTP has no answer, and
            // saying so is what lets the UI hide the row entirely.
            assert_eq!(rc, ERR_NOT_FOUND);
        }
    }
    unsafe { vault_ffi_vault_free(handle) };
}

// ---- device-unlock surface (ABI v4) ---------------------------------

/// A serialized vault with NO device unlock — what a phone actually starts
/// from. `sample_vault` already has it enabled, which would only exercise
/// the re-enrolment path.
fn password_only_vault() -> Vec<u8> {
    use vault_core::{Item, KdfAlgorithm, KdfParams};
    let params = KdfParams {
        algorithm: KdfAlgorithm::Argon2id,
        m_cost_kib: 256,
        t_cost: 1,
        p_cost: 1,
        salt: vec![3u8; KdfParams::SALT_LEN],
    };
    let mut v = Vault::create("pw", params).unwrap();
    v.upsert_item(Item::new(
        VaultItem::Login {
            title: "GitHub".into(),
            username: "alice@example.test".into(),
            password: "s3cr3t-pw".into(),
            url: "https://github.com/login".into(),
            totp_secret: None,
            notes: String::new(),
        },
        0,
    ))
    .unwrap();
    v.to_bytes().unwrap()
}

fn open_with_password(bytes: &[u8], password: &str) -> *mut VaultHandle {
    let mut handle: *mut VaultHandle = ptr::null_mut();
    let pw = CString::new(password).unwrap();
    let rc = unsafe {
        vault_ffi_vault_open_password(bytes.as_ptr(), bytes.len(), pw.as_ptr(), &mut handle)
    };
    assert_eq!(rc, OK);
    handle
}

/// The whole point of v4: a client that only knows the master password can
/// mint a quick-unlock key, and what comes back actually works.
#[test]
fn enabling_device_unlock_yields_a_key_and_a_vault_that_opens_with_it() {
    let original = password_only_vault();
    let handle = open_with_password(&original, "pw");
    assert_eq!(unsafe { vault_ffi_has_device_unlock(handle) }, 0);

    let (mut key, mut key_len) = (ptr::null_mut(), 0usize);
    let (mut bytes, mut bytes_len) = (ptr::null_mut(), 0usize);
    let rc = unsafe {
        vault_ffi_enable_device_unlock(handle, &mut key, &mut key_len, &mut bytes, &mut bytes_len)
    };
    assert_eq!(rc, OK);
    assert_eq!(key_len, KEY_LEN);
    assert!(bytes_len > 0);
    assert_eq!(unsafe { vault_ffi_has_device_unlock(handle) }, 1);

    let key_bytes = unsafe { slice::from_raw_parts(key, key_len).to_vec() };
    let new_vault = unsafe { slice::from_raw_parts(bytes, bytes_len).to_vec() };
    unsafe {
        vault_ffi_free(key, key_len);
        vault_ffi_free(bytes, bytes_len);
        vault_ffi_vault_free(handle);
    }

    // The returned key opens the returned bytes...
    let mut device_handle: *mut VaultHandle = ptr::null_mut();
    assert_eq!(
        unsafe {
            vault_ffi_vault_open(
                new_vault.as_ptr(),
                new_vault.len(),
                key_bytes.as_ptr(),
                key_bytes.len(),
                &mut device_handle,
            )
        },
        OK
    );
    // ...and the vault behind it is whole, not a husk that merely parsed.
    let (mut json, mut json_len) = (ptr::null_mut(), 0usize);
    assert_eq!(
        unsafe { vault_ffi_identities(device_handle, &mut json, &mut json_len) },
        OK
    );
    let listed =
        unsafe { std::str::from_utf8(slice::from_raw_parts(json, json_len)).unwrap() }.to_string();
    assert!(listed.contains("github.com"));
    unsafe {
        vault_ffi_free(json, json_len);
        vault_ffi_vault_free(device_handle);
    }

    // THE property that matters: enabling quick unlock must not cost the
    // user their master password. Locking someone out of their own vault is
    // unrecoverable — there is no reset.
    let still_mine = open_with_password(&new_vault, "pw");
    assert!(!still_mine.is_null());
    unsafe { vault_ffi_vault_free(still_mine) };

    // And a wrong device key is still refused by the new file.
    let mut bad: *mut VaultHandle = ptr::null_mut();
    assert_eq!(
        unsafe {
            vault_ffi_vault_open(
                new_vault.as_ptr(),
                new_vault.len(),
                [9u8; KEY_LEN].as_ptr(),
                KEY_LEN,
                &mut bad,
            )
        },
        ERR_DECRYPT
    );
    assert!(bad.is_null());
}

// ---- writes ----------------------------------------------------------

/// Insert a login through the C ABI, then prove the RETURNED bytes are a
/// real vault that contains it — the caller persists those bytes, so if the
/// item only existed in the handle the change would be lost on next launch.
#[test]
fn upsert_login_returns_vault_bytes_that_contain_the_new_item() {
    let bytes = password_only_vault();
    let handle = open_with_password(&bytes, "pw");

    let (title, user, pass, url) = (
        CString::new("Fastmail").unwrap(),
        CString::new("alice@example.test").unwrap(),
        CString::new("s3cret").unwrap(),
        CString::new("https://fastmail.com").unwrap(),
    );
    let (mut vb, mut vb_len) = (ptr::null_mut(), 0usize);
    let (mut idp, mut id_len) = (ptr::null_mut(), 0usize);
    let rc = unsafe {
        vault_ffi_upsert_login(
            handle,
            ptr::null(),
            title.as_ptr(),
            user.as_ptr(),
            pass.as_ptr(),
            url.as_ptr(),
            ptr::null(),
            ptr::null(),
            1_000,
            &mut vb,
            &mut vb_len,
            &mut idp,
            &mut id_len,
        )
    };
    assert_eq!(rc, OK);
    assert!(vb_len > 0 && id_len > 0);

    let new_bytes = unsafe { slice::from_raw_parts(vb, vb_len) }.to_vec();
    let new_id = String::from_utf8(unsafe { slice::from_raw_parts(idp, id_len) }.to_vec()).unwrap();
    unsafe {
        vault_ffi_free(vb, vb_len);
        vault_ffi_free(idp, id_len);
    }

    // Reopen the PERSISTED bytes, not the handle.
    let mut reopened = Vault::from_bytes(&new_bytes).unwrap();
    reopened.unlock("pw").unwrap();
    let item = reopened
        .get_item(uuid::Uuid::parse_str(&new_id).unwrap())
        .unwrap();
    match &item.data {
        VaultItem::Login {
            title,
            username,
            password,
            totp_secret,
            ..
        } => {
            assert_eq!(title, "Fastmail");
            assert_eq!(username, "alice@example.test");
            assert_eq!(password, "s3cret");
            // A NULL totp pointer must not become Some("").
            assert!(totp_secret.is_none());
        }
        other => panic!("expected a login, got {other:?}"),
    }
    unsafe { vault_ffi_vault_free(handle) };
}

/// The four TOTP intents at the write surface, and the reason each exists.
///
/// The killer was Keep: the detail surface never hands the secret out, so a
/// client editing a login cannot round-trip it — and before v11 that meant
/// renaming a login on the phone silently destroyed its verification code.
#[test]
fn editing_without_the_totp_field_keeps_the_code() {
    let bytes = password_only_vault();
    let handle = open_with_password(&bytes, "pw");
    let mk = |s: &str| CString::new(s).unwrap();

    let upsert = |id: Option<&str>, totp: Option<&str>| -> String {
        let id_c = id.map(|s| CString::new(s).unwrap());
        let totp_c = totp.map(|s| CString::new(s).unwrap());
        let (mut vb, mut vb_len) = (ptr::null_mut(), 0usize);
        let (mut idp, mut id_len) = (ptr::null_mut(), 0usize);
        let rc = unsafe {
            vault_ffi_upsert_login(
                handle,
                id_c.as_ref().map_or(ptr::null(), |c| c.as_ptr()),
                mk("GitHub").as_ptr(),
                mk("frank").as_ptr(),
                mk("pw").as_ptr(),
                mk("https://github.com").as_ptr(),
                totp_c.as_ref().map_or(ptr::null(), |c| c.as_ptr()),
                ptr::null(),
                1_000,
                &mut vb,
                &mut vb_len,
                &mut idp,
                &mut id_len,
            )
        };
        assert_eq!(rc, OK);
        let out =
            String::from_utf8(unsafe { slice::from_raw_parts(idp, id_len) }.to_vec()).unwrap();
        unsafe {
            vault_ffi_free(vb, vb_len);
            vault_ffi_free(idp, id_len);
        }
        out
    };
    let has_code = |id: &str| -> bool {
        let id_c = CString::new(id).unwrap();
        let (mut out, mut len) = (ptr::null_mut(), 0usize);
        let rc = unsafe { vault_ffi_totp(handle, id_c.as_ptr(), &mut out, &mut len) };
        if rc == OK {
            unsafe { vault_ffi_free(out, len) };
        }
        rc == OK
    };

    // Set — via a full otpauth URI, exactly what a QR code yields. Stored
    // normalized, so derivation works.
    let id = upsert(
        None,
        Some("otpauth://totp/GitHub:frank?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"),
    );
    assert!(has_code(&id), "the scanned URI must produce a working code");

    // Keep — an edit that never touched the field. This is the data-loss
    // case: it must NOT clear the code.
    let same = upsert(Some(&id), None);
    assert_eq!(same, id);
    assert!(
        has_code(&id),
        "editing another field must not destroy the code"
    );

    // Clear — the empty string is the explicit removal.
    upsert(Some(&id), Some(""));
    assert!(!has_code(&id), "an explicit clear must actually clear");

    // A garbage URI is refused at save, where the caller can re-scan —
    // not stored to fail later as a code that derives nonsense.
    let bad = CString::new("otpauth://totp/x?secret=NOT!BASE32").unwrap();
    let (mut vb, mut vb_len) = (ptr::null_mut(), 0usize);
    let (mut idp, mut id_len) = (ptr::null_mut(), 0usize);
    let id_c = CString::new(id).unwrap();
    let rc = unsafe {
        vault_ffi_upsert_login(
            handle,
            id_c.as_ptr(),
            mk("GitHub").as_ptr(),
            mk("frank").as_ptr(),
            mk("pw").as_ptr(),
            mk("https://github.com").as_ptr(),
            bad.as_ptr(),
            ptr::null(),
            1_000,
            &mut vb,
            &mut vb_len,
            &mut idp,
            &mut id_len,
        )
    };
    assert_eq!(rc, ERR_OP_FAILED);
    unsafe { vault_ffi_vault_free(handle) };
}

#[test]
fn check_accepts_a_vault_and_refuses_anything_else() {
    let bytes = password_only_vault();
    assert_eq!(
        unsafe { vault_ffi_vault_check(bytes.as_ptr(), bytes.len()) },
        OK
    );
    for junk in [
        b"".as_slice(),
        b"not a vault",
        b"SYBRVLT9-from-a-newer-arca",
    ] {
        assert_ne!(
            unsafe { vault_ffi_vault_check(junk.as_ptr(), junk.len()) },
            OK
        );
    }
    assert_eq!(
        unsafe { vault_ffi_vault_check(ptr::null(), 0) },
        ERR_NULL_ARG
    );
}

/// iOS never shows a login's notes, so every phone edit sends none.
/// Before v17 that erased them — recovery codes, security answers — and
/// sync carried the loss to every device. NULL keeps; "" clears.
#[test]
fn editing_without_the_notes_field_keeps_the_notes() {
    let bytes = password_only_vault();
    let handle = open_with_password(&bytes, "pw");
    let mk = |s: &str| CString::new(s).unwrap();
    let opt = |s: Option<&str>| s.map(|s| CString::new(s).unwrap());
    let ptr_of = |c: &Option<CString>| c.as_ref().map_or(ptr::null(), |c| c.as_ptr());
    let finish = |rc: i32, vb: *mut u8, vb_len: usize, idp: *mut u8, id_len: usize| {
        assert_eq!(rc, OK);
        let (bytes, id) = unsafe {
            (
                slice::from_raw_parts(vb, vb_len).to_vec(),
                String::from_utf8(slice::from_raw_parts(idp, id_len).to_vec()).unwrap(),
            )
        };
        unsafe {
            vault_ffi_free(vb, vb_len);
            vault_ffi_free(idp, id_len);
        }
        (id, bytes)
    };
    let notes_in = |bytes: &[u8], id: &str| -> String {
        let mut vault = Vault::from_bytes(bytes).unwrap();
        vault.unlock("pw").unwrap();
        match &vault
            .get_item(uuid::Uuid::parse_str(id).unwrap())
            .unwrap()
            .data
        {
            VaultItem::Login { notes, .. } | VaultItem::Wifi { notes, .. } => notes.clone(),
            other => panic!("unexpected {other:?}"),
        }
    };
    let login = |id: Option<&str>, notes: Option<&str>| {
        let (id, notes) = (opt(id), opt(notes));
        let (mut vb, mut vb_len, mut idp, mut id_len) =
            (ptr::null_mut(), 0usize, ptr::null_mut(), 0usize);
        let rc = unsafe {
            vault_ffi_upsert_login(
                handle,
                ptr_of(&id),
                mk("Bank").as_ptr(),
                mk("me").as_ptr(),
                mk("pw").as_ptr(),
                mk("https://bank.example").as_ptr(),
                ptr::null(),
                ptr_of(&notes),
                1_000,
                &mut vb,
                &mut vb_len,
                &mut idp,
                &mut id_len,
            )
        };
        finish(rc, vb, vb_len, idp, id_len)
    };
    let wifi = |id: Option<&str>, notes: Option<&str>| {
        let (id, notes) = (opt(id), opt(notes));
        let (mut vb, mut vb_len, mut idp, mut id_len) =
            (ptr::null_mut(), 0usize, ptr::null_mut(), 0usize);
        let rc = unsafe {
            vault_ffi_upsert_wifi(
                handle,
                ptr_of(&id),
                mk("Home").as_ptr(),
                mk("home-5g").as_ptr(),
                mk("pw").as_ptr(),
                mk("WPA").as_ptr(),
                0,
                ptr_of(&notes),
                1_000,
                &mut vb,
                &mut vb_len,
                &mut idp,
                &mut id_len,
            )
        };
        finish(rc, vb, vb_len, idp, id_len)
    };

    let (id, _) = login(None, Some("recovery codes: 1111 2222"));
    let (_, bytes) = login(Some(&id), None);
    assert_eq!(notes_in(&bytes, &id), "recovery codes: 1111 2222");
    let (_, bytes) = login(Some(&id), Some(""));
    assert_eq!(notes_in(&bytes, &id), "");

    let (id, bytes) = wifi(None, None);
    assert_eq!(notes_in(&bytes, &id), "");
    let (_, _) = wifi(Some(&id), Some("router in the attic"));
    let (_, bytes) = wifi(Some(&id), None);
    assert_eq!(notes_in(&bytes, &id), "router in the attic");
    let (_, bytes) = wifi(Some(&id), Some(""));
    assert_eq!(notes_in(&bytes, &id), "");
    unsafe { vault_ffi_vault_free(handle) };
}

/// The v12 single-kind upserts: create, edit in place, and refuse a
/// cross-kind id. The guard is the part worth a test — an id from the list
/// can name ANY kind, and "edit the Wi-Fi" landing on a login would rewrite
/// a password entry as a network.
#[test]
fn wifi_and_note_upserts_create_edit_and_guard_kind() {
    let bytes = password_only_vault();
    let handle = open_with_password(&bytes, "pw");
    let mk = |s: &str| CString::new(s).unwrap();

    // Create a note.
    let (mut vb, mut vb_len) = (ptr::null_mut(), 0usize);
    let (mut idp, mut id_len) = (ptr::null_mut(), 0usize);
    let rc = unsafe {
        vault_ffi_upsert_secure_note(
            handle,
            ptr::null(),
            mk("Portkode").as_ptr(),
            mk("4187").as_ptr(),
            1_000,
            &mut vb,
            &mut vb_len,
            &mut idp,
            &mut id_len,
        )
    };
    assert_eq!(rc, OK);
    let note_id =
        String::from_utf8(unsafe { slice::from_raw_parts(idp, id_len) }.to_vec()).unwrap();
    unsafe {
        vault_ffi_free(vb, vb_len);
        vault_ffi_free(idp, id_len);
    }

    // Create a Wi-Fi entry, then edit it in place.
    let (mut vb, mut vb_len) = (ptr::null_mut(), 0usize);
    let (mut idp, mut id_len) = (ptr::null_mut(), 0usize);
    let rc = unsafe {
        vault_ffi_upsert_wifi(
            handle,
            ptr::null(),
            mk("Hjemme").as_ptr(),
            mk("FranzNet").as_ptr(),
            mk("hemmelig").as_ptr(),
            mk("WPA").as_ptr(),
            0,
            mk("").as_ptr(),
            1_000,
            &mut vb,
            &mut vb_len,
            &mut idp,
            &mut id_len,
        )
    };
    assert_eq!(rc, OK);
    let wifi_id =
        String::from_utf8(unsafe { slice::from_raw_parts(idp, id_len) }.to_vec()).unwrap();
    unsafe {
        vault_ffi_free(vb, vb_len);
        vault_ffi_free(idp, id_len);
    }

    let wifi_c = CString::new(wifi_id.clone()).unwrap();
    let (mut vb, mut vb_len) = (ptr::null_mut(), 0usize);
    let (mut idp, mut id_len) = (ptr::null_mut(), 0usize);
    let rc = unsafe {
        vault_ffi_upsert_wifi(
            handle,
            wifi_c.as_ptr(),
            mk("Hytta").as_ptr(),
            mk("FranzNet").as_ptr(),
            mk("nytt").as_ptr(),
            mk("WPA").as_ptr(),
            1,
            mk("").as_ptr(),
            2_000,
            &mut vb,
            &mut vb_len,
            &mut idp,
            &mut id_len,
        )
    };
    assert_eq!(rc, OK);
    let same = String::from_utf8(unsafe { slice::from_raw_parts(idp, id_len) }.to_vec()).unwrap();
    assert_eq!(same, wifi_id, "an edit must keep its id, not append a copy");
    unsafe {
        vault_ffi_free(vb, vb_len);
        vault_ffi_free(idp, id_len);
    }

    // The guard: a note id handed to the wifi upsert is refused.
    let note_c = CString::new(note_id).unwrap();
    let (mut vb, mut vb_len) = (ptr::null_mut(), 0usize);
    let (mut idp, mut id_len) = (ptr::null_mut(), 0usize);
    let rc = unsafe {
        vault_ffi_upsert_wifi(
            handle,
            note_c.as_ptr(),
            mk("x").as_ptr(),
            mk("x").as_ptr(),
            mk("x").as_ptr(),
            mk("WPA").as_ptr(),
            0,
            mk("").as_ptr(),
            3_000,
            &mut vb,
            &mut vb_len,
            &mut idp,
            &mut id_len,
        )
    };
    assert_eq!(rc, ERR_NOT_FOUND, "a cross-kind edit must be refused");
    unsafe { vault_ffi_vault_free(handle) };
}

/// Editing must overwrite in place, keeping the id, rather than appending a
/// second copy — otherwise every edit on the phone duplicates the entry.
#[test]
fn upsert_with_an_id_edits_in_place() {
    let bytes = password_only_vault();
    let handle = open_with_password(&bytes, "pw");
    let mk = |s: &str| CString::new(s).unwrap();

    let (mut vb, mut vb_len) = (ptr::null_mut(), 0usize);
    let (mut idp, mut id_len) = (ptr::null_mut(), 0usize);
    unsafe {
        vault_ffi_upsert_login(
            handle,
            ptr::null(),
            mk("Old").as_ptr(),
            mk("u").as_ptr(),
            mk("p1").as_ptr(),
            mk("https://x.test").as_ptr(),
            ptr::null(),
            ptr::null(),
            1_000,
            &mut vb,
            &mut vb_len,
            &mut idp,
            &mut id_len,
        );
    }
    let id = String::from_utf8(unsafe { slice::from_raw_parts(idp, id_len) }.to_vec()).unwrap();
    unsafe {
        vault_ffi_free(vb, vb_len);
        vault_ffi_free(idp, id_len);
    }

    let id_c = CString::new(id.clone()).unwrap();
    let (mut vb2, mut vb2_len) = (ptr::null_mut(), 0usize);
    let (mut idp2, mut id2_len) = (ptr::null_mut(), 0usize);
    let rc = unsafe {
        vault_ffi_upsert_login(
            handle,
            id_c.as_ptr(),
            mk("New").as_ptr(),
            mk("u").as_ptr(),
            mk("p2").as_ptr(),
            mk("https://x.test").as_ptr(),
            ptr::null(),
            ptr::null(),
            2_000,
            &mut vb2,
            &mut vb2_len,
            &mut idp2,
            &mut id2_len,
        )
    };
    assert_eq!(rc, OK);
    let same_id =
        String::from_utf8(unsafe { slice::from_raw_parts(idp2, id2_len) }.to_vec()).unwrap();
    assert_eq!(same_id, id, "editing must keep the id");
    let new_bytes = unsafe { slice::from_raw_parts(vb2, vb2_len) }.to_vec();
    unsafe {
        vault_ffi_free(vb2, vb2_len);
        vault_ffi_free(idp2, id2_len);
    }

    let mut reopened = Vault::from_bytes(&new_bytes).unwrap();
    reopened.unlock("pw").unwrap();
    assert_eq!(
        reopened.list_items(false).unwrap().len(),
        2,
        "edited, not duplicated"
    );
    unsafe { vault_ffi_vault_free(handle) };
}

#[test]
fn upsert_rejects_an_unknown_id_and_bad_utf8_id() {
    let bytes = password_only_vault();
    let handle = open_with_password(&bytes, "pw");
    let mk = |s: &str| CString::new(s).unwrap();
    let (mut vb, mut vb_len) = (ptr::null_mut(), 0usize);
    let (mut idp, mut id_len) = (ptr::null_mut(), 0usize);

    for bad in ["not-a-uuid", "00000000-0000-0000-0000-000000000000"] {
        let id = mk(bad);
        let rc = unsafe {
            vault_ffi_upsert_login(
                handle,
                id.as_ptr(),
                mk("T").as_ptr(),
                mk("u").as_ptr(),
                mk("p").as_ptr(),
                mk("https://x.test").as_ptr(),
                ptr::null(),
                ptr::null(),
                1_000,
                &mut vb,
                &mut vb_len,
                &mut idp,
                &mut id_len,
            )
        };
        assert_eq!(rc, ERR_NOT_FOUND, "{bad} should not create anything");
        assert!(vb.is_null(), "no bytes on the error path");
    }
    unsafe { vault_ffi_vault_free(handle) };
}

#[test]
fn delete_soft_deletes_and_is_visible_in_the_returned_bytes() {
    let bytes = password_only_vault();
    let handle = open_with_password(&bytes, "pw");
    let mk = |s: &str| CString::new(s).unwrap();
    let (mut vb, mut vb_len) = (ptr::null_mut(), 0usize);
    let (mut idp, mut id_len) = (ptr::null_mut(), 0usize);
    unsafe {
        vault_ffi_upsert_login(
            handle,
            ptr::null(),
            mk("Temp").as_ptr(),
            mk("u").as_ptr(),
            mk("p").as_ptr(),
            mk("https://x.test").as_ptr(),
            ptr::null(),
            ptr::null(),
            1_000,
            &mut vb,
            &mut vb_len,
            &mut idp,
            &mut id_len,
        );
    }
    let id = String::from_utf8(unsafe { slice::from_raw_parts(idp, id_len) }.to_vec()).unwrap();
    unsafe {
        vault_ffi_free(vb, vb_len);
        vault_ffi_free(idp, id_len);
    }

    let id_c = CString::new(id.clone()).unwrap();
    let (mut db, mut db_len) = (ptr::null_mut(), 0usize);
    let rc = unsafe { vault_ffi_delete_item(handle, id_c.as_ptr(), 3_000, &mut db, &mut db_len) };
    assert_eq!(rc, OK);
    let after = unsafe { slice::from_raw_parts(db, db_len) }.to_vec();
    unsafe { vault_ffi_free(db, db_len) };

    let mut reopened = Vault::from_bytes(&after).unwrap();
    reopened.unlock("pw").unwrap();
    // Soft delete: gone from the active list, still in the Trash.
    assert!(reopened
        .list_items(false)
        .unwrap()
        .iter()
        .all(|i| i.title != "Temp"));
    assert!(reopened
        .list_items(true)
        .unwrap()
        .iter()
        .any(|i| i.title == "Temp"));
    unsafe { vault_ffi_vault_free(handle) };
}

#[test]
fn writes_are_refused_on_a_locked_or_null_handle() {
    let mk = |s: &str| CString::new(s).unwrap();
    let (mut vb, mut vb_len) = (ptr::null_mut(), 0usize);
    let (mut idp, mut id_len) = (ptr::null_mut(), 0usize);
    let rc = unsafe {
        vault_ffi_upsert_login(
            ptr::null_mut(),
            ptr::null(),
            mk("T").as_ptr(),
            mk("u").as_ptr(),
            mk("p").as_ptr(),
            mk("https://x.test").as_ptr(),
            ptr::null(),
            ptr::null(),
            1_000,
            &mut vb,
            &mut vb_len,
            &mut idp,
            &mut id_len,
        )
    };
    assert_eq!(rc, ERR_NULL_ARG);
    let rc = unsafe {
        vault_ffi_delete_item(ptr::null_mut(), mk("x").as_ptr(), 1, &mut vb, &mut vb_len)
    };
    assert_eq!(rc, ERR_NULL_ARG);
}

/// Turning it off has to strip the wrapping from the FILE. Deleting the
/// keychain item alone would leave the wrapped key in the vault, where it
/// travels to every device the vault syncs to.
#[test]
fn disabling_device_unlock_revokes_the_key_in_the_file() {
    let (original, device_key, _id) = sample_vault();
    let handle = open_with_password(&original, "pw");
    assert_eq!(unsafe { vault_ffi_has_device_unlock(handle) }, 1);

    let (mut bytes, mut bytes_len) = (ptr::null_mut(), 0usize);
    let rc = unsafe { vault_ffi_disable_device_unlock(handle, &mut bytes, &mut bytes_len) };
    assert_eq!(rc, OK);
    assert_eq!(unsafe { vault_ffi_has_device_unlock(handle) }, 0);
    let new_vault = unsafe { slice::from_raw_parts(bytes, bytes_len).to_vec() };
    unsafe {
        vault_ffi_free(bytes, bytes_len);
        vault_ffi_vault_free(handle);
    }

    // The key that used to work no longer does.
    let mut revoked: *mut VaultHandle = ptr::null_mut();
    assert_eq!(
        unsafe {
            vault_ffi_vault_open(
                new_vault.as_ptr(),
                new_vault.len(),
                device_key.as_ptr(),
                device_key.len(),
                &mut revoked,
            )
        },
        ERR_DECRYPT
    );
    assert!(revoked.is_null());

    // The master password still does.
    let still_mine = open_with_password(&new_vault, "pw");
    assert!(!still_mine.is_null());
    unsafe { vault_ffi_vault_free(still_mine) };
}

/// Re-enrolling replaces the key rather than adding a second one, so a
/// device key that leaked can be rotated away.
#[test]
fn re_enrolling_invalidates_the_previous_device_key() {
    let (original, old_key, _id) = sample_vault();
    let handle = open_with_password(&original, "pw");

    let (mut key, mut key_len) = (ptr::null_mut(), 0usize);
    let (mut bytes, mut bytes_len) = (ptr::null_mut(), 0usize);
    assert_eq!(
        unsafe {
            vault_ffi_enable_device_unlock(
                handle,
                &mut key,
                &mut key_len,
                &mut bytes,
                &mut bytes_len,
            )
        },
        OK
    );
    let new_key = unsafe { slice::from_raw_parts(key, key_len).to_vec() };
    let new_vault = unsafe { slice::from_raw_parts(bytes, bytes_len).to_vec() };
    assert_ne!(new_key.as_slice(), old_key.as_slice());
    unsafe {
        vault_ffi_free(key, key_len);
        vault_ffi_free(bytes, bytes_len);
        vault_ffi_vault_free(handle);
    }

    let mut stale: *mut VaultHandle = ptr::null_mut();
    assert_eq!(
        unsafe {
            vault_ffi_vault_open(
                new_vault.as_ptr(),
                new_vault.len(),
                old_key.as_ptr(),
                old_key.len(),
                &mut stale,
            )
        },
        ERR_DECRYPT
    );
    assert!(stale.is_null());
}

#[test]
fn device_unlock_rejects_null_arguments_without_dereferencing_them() {
    let (mut a, mut al) = (ptr::null_mut(), 0usize);
    assert_eq!(
        unsafe {
            vault_ffi_enable_device_unlock(ptr::null_mut(), &mut a, &mut al, &mut a, &mut al)
        },
        ERR_NULL_ARG
    );
    assert_eq!(
        unsafe { vault_ffi_disable_device_unlock(ptr::null_mut(), &mut a, &mut al) },
        ERR_NULL_ARG
    );
    assert_eq!(
        unsafe { vault_ffi_has_device_unlock(ptr::null_mut()) },
        ERR_NULL_ARG
    );

    // A valid handle with null out-pointers must also be refused, not
    // written through.
    let bytes = password_only_vault();
    let handle = open_with_password(&bytes, "pw");
    assert_eq!(
        unsafe {
            vault_ffi_enable_device_unlock(
                handle,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        },
        ERR_NULL_ARG
    );
    // Refused cleanly: the vault is untouched, so a retry still works.
    assert_eq!(unsafe { vault_ffi_has_device_unlock(handle) }, 0);
    unsafe { vault_ffi_vault_free(handle) };
}

/// The generator's promises, checked across the ABI rather than only in
/// core: a caller that switches a class off must not get it back. The core
/// test proves the algorithm; this proves the flags survive the boundary,
/// which is where an argument-order slip would land.
#[test]
fn generated_passwords_honour_the_flags_they_were_given() {
    let take = |len: usize, lo: i32, up: i32, di: i32, sy: i32| -> Option<String> {
        let mut ptr: *mut u8 = std::ptr::null_mut();
        let mut n: usize = 0;
        let rc = unsafe { vault_ffi_generate_password(len, lo, up, di, sy, &mut ptr, &mut n) };
        if rc != OK {
            return None;
        }
        let s = String::from_utf8(unsafe { std::slice::from_raw_parts(ptr, n) }.to_vec())
            .expect("generated passwords are ASCII");
        unsafe { vault_ffi_free(ptr, n) };
        Some(s)
    };

    // Digits only: proves the other three classes are actually excluded,
    // and that the length is the length asked for.
    let digits = take(32, 0, 0, 1, 0).expect("digits-only must generate");
    assert_eq!(digits.len(), 32);
    assert!(digits.chars().all(|c| c.is_ascii_digit()), "{digits:?}");

    // Every class on, long enough that each is guaranteed a slot.
    let all = take(40, 1, 1, 1, 1).expect("all classes must generate");
    assert!(all.chars().any(|c| c.is_ascii_lowercase()));
    assert!(all.chars().any(|c| c.is_ascii_uppercase()));
    assert!(all.chars().any(|c| c.is_ascii_digit()));
    assert!(all.chars().any(|c| !c.is_ascii_alphanumeric()));

    // Two passwords in a row are not the same one. A generator wired to a
    // seeded or stuck RNG passes every test above and none of its purpose.
    assert_ne!(take(24, 1, 1, 1, 1), take(24, 1, 1, 1, 1));

    // Refused, not silently defaulted.
    assert!(take(0, 1, 1, 1, 1).is_none(), "zero length must be refused");
    assert!(take(20, 0, 0, 0, 0).is_none(), "no classes must be refused");
}

/// include/vault_ffi.h is the contract Swift compiles against, and it is
/// maintained by hand — it sat claiming "ABI version 2" for a v3 library,
/// which is exactly the drift a client checking the version would trust.
#[test]
fn the_header_names_the_abi_it_documents() {
    let header = include_str!("../include/vault_ffi.h");
    let expected = format!("ABI version {ABI_VERSION}");
    assert!(
        header.contains(&expected),
        "vault_ffi.h does not say {expected:?} — bump it with ABI_VERSION"
    );
}

/// The other half of the same promise: an export with no declaration is
/// invisible to Swift until someone notices, and adding one is precisely
/// when this file is easy to forget.
#[test]
fn every_export_is_declared_in_the_header() {
    let header = include_str!("../include/vault_ffi.h");
    let mut checked = 0;
    // Both files: the sync surface lives in sync.rs, and a scan that only
    // read lib.rs would quietly stop covering the newest exports — which is
    // the exact moment this check earns its keep.
    let sources = [
        include_str!("lib.rs"),
        include_str!("passkey.rs"),
        include_str!("write.rs"),
        include_str!("sync.rs"),
    ];
    for line in sources.iter().flat_map(|src| src.lines()) {
        let line = line.trim();
        let Some(rest) = line
            .strip_prefix("pub extern \"C\" fn ")
            .or_else(|| line.strip_prefix("pub unsafe extern \"C\" fn "))
        else {
            continue;
        };
        let name = rest.split('(').next().unwrap_or_default();
        // Look for an actual declaration line, not the name anywhere: a
        // bare `contains(name)` matches a prose mention in the header's
        // comments, and matches `<name>X` too, so a renamed export would
        // sail past.
        let declared = header.lines().any(|l| {
            let l = l.trim_start();
            (l.starts_with("int32_t ") || l.starts_with("void "))
                && l.contains(&format!(" {name}("))
        });
        assert!(
            declared,
            "{name} is exported but not declared in include/vault_ffi.h"
        );
        checked += 1;
    }
    // Guard against the scan silently matching nothing (a formatting change
    // that splits the signature across lines would do it).
    assert!(checked >= 17, "only found {checked} exports to check");
}

// A client with no device key (a phone on first launch) must still be able
// to open the vault. Without this the FFI is unusable on its own: every
// caller would depend on some other process having minted a device key
// into the keychain first.
#[test]
fn opens_with_the_master_password_and_rejects_a_wrong_one() {
    let (bytes, _device, id) = sample_vault();

    let mut handle: *mut VaultHandle = std::ptr::null_mut();
    let pw = std::ffi::CString::new("pw").unwrap();
    let rc = unsafe {
        vault_ffi_vault_open_password(bytes.as_ptr(), bytes.len(), pw.as_ptr(), &mut handle)
    };
    assert_eq!(rc, OK);
    assert!(!handle.is_null());

    // The handle is fully usable, not a half-open shell.
    let mut out: *mut u8 = std::ptr::null_mut();
    let mut len = 0usize;
    let cid = std::ffi::CString::new(id).unwrap();
    assert_eq!(
        unsafe { vault_ffi_password_for_id(handle, cid.as_ptr(), &mut out, &mut len) },
        OK
    );
    unsafe { vault_ffi_free(out, len) };
    unsafe { vault_ffi_vault_free(handle) };

    // A wrong password must fail closed, and leave no handle behind.
    let mut bad_handle: *mut VaultHandle = std::ptr::null_mut();
    let bad = std::ffi::CString::new("not-the-password").unwrap();
    let rc = unsafe {
        vault_ffi_vault_open_password(bytes.as_ptr(), bytes.len(), bad.as_ptr(), &mut bad_handle)
    };
    assert_eq!(rc, ERR_DECRYPT);
    assert!(bad_handle.is_null(), "no handle on the error path");

    // Null arguments are rejected, not dereferenced.
    let mut h: *mut VaultHandle = std::ptr::null_mut();
    assert_eq!(
        unsafe { vault_ffi_vault_open_password(std::ptr::null(), 0, pw.as_ptr(), &mut h) },
        ERR_NULL_ARG
    );
}

#[test]
fn open_list_fetch_free_round_trip() {
    let (bytes, key, id) = sample_vault();

    let mut handle: *mut VaultHandle = ptr::null_mut();
    let rc = unsafe {
        vault_ffi_vault_open(
            bytes.as_ptr(),
            bytes.len(),
            key.as_ptr(),
            key.len(),
            &mut handle,
        )
    };
    assert_eq!(rc, OK);
    assert!(!handle.is_null());

    // identities: metadata only, no password.
    let (mut json, mut json_len) = (ptr::null_mut(), 0usize);
    assert_eq!(
        unsafe { vault_ffi_identities(handle, &mut json, &mut json_len) },
        OK
    );
    let json_str = unsafe { std::str::from_utf8(slice::from_raw_parts(json, json_len)).unwrap() };
    assert!(json_str.contains("\"user\":\"alice@example.test\""));
    assert!(json_str.contains("\"domain\":\"github.com\""));
    assert!(json_str.contains(&format!("\"id\":\"{id}\"")));
    assert!(!json_str.contains("s3cr3t-pw"));
    unsafe { vault_ffi_free(json, json_len) };

    // password for that id.
    let cid = CString::new(id).unwrap();
    let (mut pw, mut pw_len) = (ptr::null_mut(), 0usize);
    assert_eq!(
        unsafe { vault_ffi_password_for_id(handle, cid.as_ptr(), &mut pw, &mut pw_len) },
        OK
    );
    assert_eq!(unsafe { slice::from_raw_parts(pw, pw_len) }, b"s3cr3t-pw");
    unsafe { vault_ffi_free(pw, pw_len) };

    unsafe { vault_ffi_vault_free(handle) };
}

#[test]
fn wrong_device_key_refuses_without_leaking() {
    let (bytes, _key, _id) = sample_vault();
    let bad = [9u8; KEY_LEN];
    let mut handle: *mut VaultHandle = ptr::null_mut();
    let rc = unsafe {
        vault_ffi_vault_open(
            bytes.as_ptr(),
            bytes.len(),
            bad.as_ptr(),
            bad.len(),
            &mut handle,
        )
    };
    assert_eq!(rc, ERR_DECRYPT);
    assert!(handle.is_null());
}

#[test]
fn bad_key_length_is_rejected() {
    let (bytes, _key, _id) = sample_vault();
    let short = [0u8; 16];
    let mut handle: *mut VaultHandle = ptr::null_mut();
    let rc = unsafe {
        vault_ffi_vault_open(
            bytes.as_ptr(),
            bytes.len(),
            short.as_ptr(),
            short.len(),
            &mut handle,
        )
    };
    assert_eq!(rc, ERR_BAD_KEY_LEN);
    assert!(handle.is_null());
}

#[test]
fn unknown_id_is_not_found() {
    let (bytes, key, _id) = sample_vault();
    let mut handle: *mut VaultHandle = ptr::null_mut();
    unsafe {
        vault_ffi_vault_open(
            bytes.as_ptr(),
            bytes.len(),
            key.as_ptr(),
            key.len(),
            &mut handle,
        );
    }
    let other = CString::new(uuid::Uuid::from_bytes([1; 16]).to_string()).unwrap();
    let (mut pw, mut pw_len) = (ptr::null_mut(), 0usize);
    let rc = unsafe { vault_ffi_password_for_id(handle, other.as_ptr(), &mut pw, &mut pw_len) };
    assert_eq!(rc, ERR_NOT_FOUND);
    unsafe { vault_ffi_vault_free(handle) };
}

#[test]
fn null_handle_and_free_are_safe() {
    let (mut j, mut jl) = (ptr::null_mut(), 0usize);
    assert_eq!(
        unsafe { vault_ffi_identities(ptr::null_mut(), &mut j, &mut jl) },
        ERR_NULL_ARG
    );
    unsafe { vault_ffi_vault_free(ptr::null_mut()) }; // no-op, no crash
}

/// The write-back the sync path needs: whatever another process committed
/// to disk during the network round-trip must survive being persisted.
///
/// Before this call existed the bytes were serialized BEFORE the cycle, so
/// a passkey the AutoFill extension registered mid-cycle was written over
/// and gone.
#[test]
fn merge_and_serialize_keeps_what_another_process_wrote() {
    use vault_core::{Item, KdfAlgorithm, KdfParams, VaultItem};
    let params = KdfParams {
        algorithm: KdfAlgorithm::Argon2id,
        m_cost_kib: 256,
        t_cost: 1,
        p_cost: 1,
        salt: vec![9u8; KdfParams::SALT_LEN],
    };
    let login = |title: &str, at: i64| {
        Item::new(
            VaultItem::Login {
                title: title.into(),
                username: "u".into(),
                password: "p".into(),
                url: format!("https://{title}.test"),
                totp_secret: None,
                notes: String::new(),
            },
            at,
        )
    };

    // Shared starting point.
    let mut base = Vault::create("pw", params).unwrap();
    base.upsert_item(login("shared", 1)).unwrap();
    let base_bytes = base.to_bytes().unwrap();

    // "Our" process opens it and adds an item in memory.
    let mut handle: *mut VaultHandle = ptr::null_mut();
    let pw = CString::new("pw").unwrap();
    assert_eq!(
        unsafe {
            vault_ffi_vault_open_password(
                base_bytes.as_ptr(),
                base_bytes.len(),
                pw.as_ptr(),
                &mut handle,
            )
        },
        OK
    );
    let id = CString::new("").unwrap(); // new item
    let (mut vb, mut vl) = (ptr::null_mut(), 0usize);
    let (mut idb, mut idl) = (ptr::null_mut(), 0usize);
    let title = CString::new("ours").unwrap();
    let empty = CString::new("").unwrap();
    assert_eq!(
        unsafe {
            vault_ffi_upsert_login(
                handle,
                ptr::null(),
                title.as_ptr(),
                empty.as_ptr(),
                empty.as_ptr(),
                empty.as_ptr(),
                ptr::null(),
                empty.as_ptr(),
                2,
                &mut vb,
                &mut vl,
                &mut idb,
                &mut idl,
            )
        },
        OK
    );
    unsafe {
        vault_ffi_free(vb, vl);
        vault_ffi_free(idb, idl);
    }
    let _ = id;

    // Meanwhile ANOTHER process wrote its own new item to the same file.
    let mut theirs = Vault::from_bytes(&base_bytes).unwrap();
    theirs.unlock("pw").unwrap();
    theirs.upsert_item(login("theirs", 3)).unwrap();
    let disk = theirs.to_bytes().unwrap();

    // Merge that disk state in and serialize in one step — the operation a
    // caller performs while holding the vault lock.
    let (mut out, mut out_len) = (ptr::null_mut(), 0usize);
    assert_eq!(
        unsafe {
            vault_ffi_merge_and_serialize(handle, disk.as_ptr(), disk.len(), &mut out, &mut out_len)
        },
        OK
    );
    let written = unsafe { slice::from_raw_parts(out, out_len) }.to_vec();
    unsafe { vault_ffi_free(out, out_len) };

    // The bytes that would hit disk carry BOTH writes.
    let mut check = Vault::from_bytes(&written).unwrap();
    check.unlock("pw").unwrap();
    let mut titles: Vec<String> = check
        .list_items(false)
        .unwrap()
        .iter()
        .map(|s| s.title.clone())
        .collect();
    titles.sort();
    assert_eq!(
        titles,
        vec!["ours", "shared", "theirs"],
        "neither process's write may be lost"
    );

    // Nothing on disk yet is not an error; it just serializes.
    let (mut out2, mut out2_len) = (ptr::null_mut(), 0usize);
    assert_eq!(
        unsafe { vault_ffi_merge_and_serialize(handle, ptr::null(), 0, &mut out2, &mut out2_len) },
        OK
    );
    assert!(out2_len > 0);
    unsafe { vault_ffi_free(out2, out2_len) };

    assert_eq!(
        unsafe {
            vault_ffi_merge_and_serialize(ptr::null_mut(), ptr::null(), 0, &mut out2, &mut out2_len)
        },
        ERR_NULL_ARG
    );
    unsafe { vault_ffi_vault_free(handle) };
}

#[test]
fn merging_identical_bytes_is_a_no_op() {
    // foldInDiskState runs on EVERY write, and the common case is disk ==
    // memory. A merge that duplicated, reordered, or soft-deleted items on
    // that path would corrupt every single save. Prove it is inert.
    use vault_core::{Item, KdfAlgorithm, KdfParams, VaultItem};
    let params = KdfParams {
        algorithm: KdfAlgorithm::Argon2id,
        m_cost_kib: 256,
        t_cost: 1,
        p_cost: 1,
        salt: vec![7u8; KdfParams::SALT_LEN],
    };
    let mut v = Vault::create("pw", params).unwrap();
    for (i, t) in ["one", "two", "three"].iter().enumerate() {
        v.upsert_item(Item::new(
            VaultItem::Login {
                title: (*t).into(),
                username: "u".into(),
                password: "p".into(),
                url: format!("https://{t}.test"),
                totp_secret: None,
                notes: String::new(),
            },
            i as i64 + 1,
        ))
        .unwrap();
    }
    let bytes = v.to_bytes().unwrap();

    let mut handle: *mut VaultHandle = ptr::null_mut();
    let pw = CString::new("pw").unwrap();
    assert_eq!(
        unsafe {
            vault_ffi_vault_open_password(bytes.as_ptr(), bytes.len(), pw.as_ptr(), &mut handle)
        },
        OK
    );
    let read_titles = |h: *mut VaultHandle| -> Vec<String> {
        let (mut j, mut jl) = (ptr::null_mut(), 0usize);
        assert_eq!(unsafe { vault_ffi_items(h, &mut j, &mut jl) }, OK);
        let v: serde_json::Value =
            serde_json::from_slice(unsafe { slice::from_raw_parts(j, jl) }).unwrap();
        unsafe {
            vault_ffi_free(j, jl);
        }
        let mut t: Vec<String> = v
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|i| i["title"].as_str().map(String::from))
            .collect();
        t.sort();
        t
    };
    let before = read_titles(handle);
    // Merge the vault's OWN serialized bytes in — the disk==memory no-op.
    assert_eq!(
        unsafe { vault_ffi_merge_remote(handle, bytes.as_ptr(), bytes.len()) },
        OK
    );
    let after = read_titles(handle);
    assert_eq!(
        before, after,
        "an identical-bytes merge must not change the item set"
    );
    assert_eq!(after.len(), 3, "no item was duplicated or dropped");
    unsafe {
        vault_ffi_vault_free(handle);
    }
}

#[test]
fn merge_before_write_does_not_lose_the_other_process_write() {
    // The lost-update the review found: two processes share one vault file,
    // each with its own in-memory copy. Here process A holds V0, process B
    // adds a login and writes V1, then A registers a passkey. Without the
    // pre-write merge, A's write would serialize V0+passkey and DROP B's
    // login. With it, both survive.
    use vault_core::{Item, KdfAlgorithm, KdfParams, VaultItem};
    let params = KdfParams {
        algorithm: KdfAlgorithm::Argon2id,
        m_cost_kib: 256,
        t_cost: 1,
        p_cost: 1,
        salt: vec![7u8; KdfParams::SALT_LEN],
    };
    // V0: one login, shared starting point.
    let mut v0 = Vault::create("pw", params).unwrap();
    v0.upsert_item(Item::new(
        VaultItem::Login {
            title: "A".into(),
            username: "a".into(),
            password: "p".into(),
            url: "https://a.test".into(),
            totp_secret: None,
            notes: String::new(),
        },
        1,
    ))
    .unwrap();
    let v0_bytes = v0.to_bytes().unwrap();

    // Process B: open V0, add login B, write V1 to "disk".
    let mut b_handle: *mut VaultHandle = ptr::null_mut();
    let pw = CString::new("pw").unwrap();
    assert_eq!(
        unsafe {
            vault_ffi_vault_open_password(
                v0_bytes.as_ptr(),
                v0_bytes.len(),
                pw.as_ptr(),
                &mut b_handle,
            )
        },
        OK
    );
    let (title, user, pass, url, notes) = (
        CString::new("B").unwrap(),
        CString::new("b").unwrap(),
        CString::new("p").unwrap(),
        CString::new("https://b.test").unwrap(),
        CString::new("").unwrap(),
    );
    let (mut vb, mut vbl, mut ib, mut ibl) = (ptr::null_mut(), 0usize, ptr::null_mut(), 0usize);
    assert_eq!(
        unsafe {
            vault_ffi_upsert_login(
                b_handle,
                ptr::null(),
                title.as_ptr(),
                user.as_ptr(),
                pass.as_ptr(),
                url.as_ptr(),
                ptr::null(),
                notes.as_ptr(),
                2,
                &mut vb,
                &mut vbl,
                &mut ib,
                &mut ibl,
            )
        },
        OK
    );
    let v1_bytes = unsafe { slice::from_raw_parts(vb, vbl) }.to_vec();
    unsafe {
        vault_ffi_free(vb, vbl);
        vault_ffi_free(ib, ibl);
        vault_ffi_vault_free(b_handle);
    }

    // Process A: still on V0. Fold in V1 (what is now on disk), THEN register.
    let mut a_handle: *mut VaultHandle = ptr::null_mut();
    assert_eq!(
        unsafe {
            vault_ffi_vault_open_password(
                v0_bytes.as_ptr(),
                v0_bytes.len(),
                pw.as_ptr(),
                &mut a_handle,
            )
        },
        OK
    );
    assert_eq!(
        unsafe { vault_ffi_merge_remote(a_handle, v1_bytes.as_ptr(), v1_bytes.len()) },
        OK
    );
    let rp = CString::new("github.com").unwrap();
    let un = CString::new("frank").unwrap();
    let (mut va, mut val, mut cid, mut cidl, mut ao, mut aol) = (
        ptr::null_mut(),
        0usize,
        ptr::null_mut(),
        0usize,
        ptr::null_mut(),
        0usize,
    );
    assert_eq!(
        unsafe {
            vault_ffi_passkey_register(
                a_handle,
                rp.as_ptr(),
                un.as_ptr(),
                ptr::null(),
                0,
                true,
                3,
                &mut va,
                &mut val,
                &mut cid,
                &mut cidl,
                &mut ao,
                &mut aol,
            )
        },
        OK
    );
    let final_bytes = unsafe { slice::from_raw_parts(va, val) }.to_vec();
    unsafe {
        vault_ffi_free(va, val);
        vault_ffi_free(cid, cidl);
        vault_ffi_free(ao, aol);
        vault_ffi_vault_free(a_handle);
    }

    // Reopen the final vault: A's login, B's login, AND the passkey.
    let mut fin: *mut VaultHandle = ptr::null_mut();
    assert_eq!(
        unsafe {
            vault_ffi_vault_open_password(
                final_bytes.as_ptr(),
                final_bytes.len(),
                pw.as_ptr(),
                &mut fin,
            )
        },
        OK
    );
    let (mut j, mut jl) = (ptr::null_mut(), 0usize);
    assert_eq!(unsafe { vault_ffi_items(fin, &mut j, &mut jl) }, OK);
    let items: serde_json::Value =
        serde_json::from_slice(unsafe { slice::from_raw_parts(j, jl) }).unwrap();
    unsafe {
        vault_ffi_free(j, jl);
    }
    let titles: Vec<String> = items
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|i| i["title"].as_str().map(String::from))
        .collect();
    assert!(
        titles.iter().any(|t| t == "A"),
        "A's login must survive: {titles:?}"
    );
    assert!(
        titles.iter().any(|t| t == "B"),
        "B's login (the other process) must NOT be lost: {titles:?}"
    );
    // The passkey has title == rp_id.
    assert!(
        titles.iter().any(|t| t == "github.com"),
        "the registered passkey must be present: {titles:?}"
    );
    unsafe {
        vault_ffi_vault_free(fin);
    }
}

#[test]
fn new_registration_preserves_existing_credentials_for_the_same_account() {
    let handle = open_with_password(&password_only_vault(), "pw");
    let rp = CString::new("example.com").unwrap();
    let user = CString::new("account").unwrap();
    let user_handle = [9u8; 16];
    let mut ids = Vec::new();
    for now in [1, 2] {
        let (mut bytes, mut bytes_len, mut cred, mut cred_len, mut att, mut att_len) =
            (ptr::null_mut(), 0, ptr::null_mut(), 0, ptr::null_mut(), 0);
        assert_eq!(
            unsafe {
                vault_ffi_passkey_register(
                    handle,
                    rp.as_ptr(),
                    user.as_ptr(),
                    user_handle.as_ptr(),
                    user_handle.len(),
                    true,
                    now,
                    &mut bytes,
                    &mut bytes_len,
                    &mut cred,
                    &mut cred_len,
                    &mut att,
                    &mut att_len,
                )
            },
            OK
        );
        ids.push(unsafe { slice::from_raw_parts(cred, cred_len).to_vec() });
        unsafe {
            vault_ffi_free(bytes, bytes_len);
            vault_ffi_free(cred, cred_len);
            vault_ffi_free(att, att_len);
        }
    }
    assert_ne!(ids[0], ids[1]);
    let vault = unsafe { &*handle }.vault.lock().unwrap();
    let items = vault.list_items(false).unwrap();
    for credential_id in ids {
        assert!(items
            .iter()
            .any(|item| matches!(&vault.get_item(item.id).unwrap().data,
            VaultItem::Passkey { credential_id: stored, .. } if *stored == credential_id)));
    }
    drop(vault);
    unsafe { vault_ffi_vault_free(handle) };
}

#[test]
fn passkey_register_stores_and_the_attestation_verifies() {
    use vault_core::{KdfAlgorithm, KdfParams};
    let params = KdfParams {
        algorithm: KdfAlgorithm::Argon2id,
        m_cost_kib: 256,
        t_cost: 1,
        p_cost: 1,
        salt: vec![7u8; KdfParams::SALT_LEN],
    };
    let bytes = Vault::create("pw", params).unwrap().to_bytes().unwrap();
    let mut handle: *mut VaultHandle = ptr::null_mut();
    let pw = CString::new("pw").unwrap();
    assert_eq!(
        unsafe {
            vault_ffi_vault_open_password(bytes.as_ptr(), bytes.len(), pw.as_ptr(), &mut handle)
        },
        OK
    );

    let rp = CString::new("github.com").unwrap();
    let user = CString::new("frank").unwrap();
    let user_handle = [9u8, 9, 9];
    let (mut vault_out, mut vault_len) = (ptr::null_mut(), 0usize);
    let (mut cred, mut cred_len) = (ptr::null_mut(), 0usize);
    let (mut att, mut att_len) = (ptr::null_mut(), 0usize);
    assert_eq!(
        unsafe {
            vault_ffi_passkey_register(
                handle,
                rp.as_ptr(),
                user.as_ptr(),
                user_handle.as_ptr(),
                user_handle.len(),
                true,
                123,
                &mut vault_out,
                &mut vault_len,
                &mut cred,
                &mut cred_len,
                &mut att,
                &mut att_len,
            )
        },
        OK
    );
    let new_vault = unsafe { slice::from_raw_parts(vault_out, vault_len) }.to_vec();
    let credential_id = unsafe { slice::from_raw_parts(cred, cred_len) }.to_vec();
    let attestation = unsafe { slice::from_raw_parts(att, att_len) }.to_vec();
    unsafe {
        vault_ffi_free(vault_out, vault_len);
        vault_ffi_free(cred, cred_len);
        vault_ffi_free(att, att_len);
        vault_ffi_vault_free(handle);
    }
    assert!(!credential_id.is_empty());

    // The returned vault bytes are what iOS writes to disk. REOPEN them —
    // this is the proof the private key actually landed, not merely that a
    // credential came back.
    let mut reopened: *mut VaultHandle = ptr::null_mut();
    assert_eq!(
        unsafe {
            vault_ffi_vault_open_password(
                new_vault.as_ptr(),
                new_vault.len(),
                pw.as_ptr(),
                &mut reopened,
            )
        },
        OK
    );
    let (mut rows_out, mut rows_len) = (ptr::null_mut(), 0usize);
    assert_eq!(
        unsafe { vault_ffi_passkey_identities(reopened, &mut rows_out, &mut rows_len) },
        OK
    );
    let rows: serde_json::Value =
        serde_json::from_slice(unsafe { slice::from_raw_parts(rows_out, rows_len) }).unwrap();
    unsafe { vault_ffi_free(rows_out, rows_len) };
    let rows = rows.as_array().unwrap();
    assert_eq!(rows.len(), 1, "exactly one passkey should have been stored");
    assert_eq!(rows[0]["rp_id"], "github.com");
    let stored_id = rows[0]["id"].as_str().unwrap().to_string();
    let b64 = data_encoding::BASE64;
    assert_eq!(
        b64.decode(rows[0]["credential_id"].as_str().unwrap().as_bytes())
            .unwrap(),
        credential_id,
        "the RP got the credential id that was stored"
    );

    // The stored key must sign for this credential: assert by id, then
    // verify the signature against the credential's own public key. If the
    // key had not persisted, this assertion could not be produced.
    let hash = [4u8; 32];
    let id_c = CString::new(stored_id).unwrap();
    let (mut ao, mut aol) = (ptr::null_mut(), 0usize);
    assert_eq!(
        unsafe {
            vault_ffi_passkey_assert_for_id(
                reopened,
                id_c.as_ptr(),
                hash.as_ptr(),
                hash.len(),
                1,
                &mut ao,
                &mut aol,
            )
        },
        OK
    );
    let resp: serde_json::Value =
        serde_json::from_slice(unsafe { slice::from_raw_parts(ao, aol) }).unwrap();
    unsafe { vault_ffi_free(ao, aol) };
    let auth_data = b64
        .decode(resp["authenticator_data"].as_str().unwrap().as_bytes())
        .unwrap();
    let signature = b64
        .decode(resp["signature"].as_str().unwrap().as_bytes())
        .unwrap();

    // The attestation object embeds the COSE public key; pull the SEC1 form
    // from a fresh assertion path instead by re-deriving is not available,
    // so verify the signature the same way the assert test does: against the
    // authenticator data the RP would receive.
    let mut signed = auth_data;
    signed.extend_from_slice(&hash);

    // The real end-to-end claim: the key the RP received in the attestation
    // and the key stored in the vault (which just produced this assertion)
    // are the SAME key. Recover the public key from the attestation object's
    // COSE block and verify the assertion signature against it. If register
    // had handed the site one key and stored another, this fails.
    let vk = public_key_from_attestation(&attestation);
    use p256::ecdsa::{signature::Verifier, Signature};
    let sig = Signature::from_der(&signature).expect("DER signature");
    assert!(
        vk.verify(&signed, &sig).is_ok(),
        "the stored key does not match the attestation handed to the RP"
    );

    unsafe { vault_ffi_vault_free(reopened) };
}

/// Recover the credential's public key from a WebAuthn attestationObject.
///
/// attestationObject = CBOR { fmt, attStmt, authData }. authData is
/// rpIdHash(32) | flags(1) | signCount(4) | AAGUID(16) | credIdLen(2) |
/// credId | COSE_Key. The COSE_Key is an EC2 P-256 public key; we read x/y
/// and rebuild the verifying key. Lets a test prove the stored key and the
/// attested key are one and the same.
fn public_key_from_attestation(attestation: &[u8]) -> p256::ecdsa::VerifyingKey {
    use ciborium::value::Value;
    let att: Value = ciborium::from_reader(attestation).expect("attestation CBOR");
    let map = att.as_map().expect("attestation is a map");
    let auth = map
        .iter()
        .find(|(k, _)| k.as_text() == Some("authData"))
        .and_then(|(_, v)| v.as_bytes())
        .expect("authData bytes");
    // Skip to the COSE key: 32 + 1 + 4 + 16 = 53, then 2-byte credIdLen.
    let cred_len = u16::from_be_bytes([auth[53], auth[54]]) as usize;
    let cose_start = 55 + cred_len;
    let cose: Value = ciborium::from_reader(&auth[cose_start..]).expect("COSE key CBOR");
    let entries = cose.as_map().expect("COSE map");
    let get = |label: i64| -> Vec<u8> {
        entries
            .iter()
            .find(|(k, _)| k.as_integer() == Some(label.into()))
            .and_then(|(_, v)| v.as_bytes())
            .expect("COSE coord")
            .clone()
    };
    let x = get(-2);
    let y = get(-3);
    let mut sec1 = vec![0x04u8];
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);
    p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).expect("P-256 key")
}

/// The shared file after the master password changed: a process that has
/// not taken the change on is told so, and a copy from before the change,
/// written by such a process, merges as nothing instead of failing.
#[test]
fn a_merge_reports_a_password_change_and_skips_what_it_replaced() {
    let mut params = vault_core::KdfParams::new_default().unwrap();
    params.m_cost_kib = 256;
    params.t_cost = 1;
    let mut vault = Vault::create("old", params).unwrap();
    let before = vault.to_bytes().unwrap();
    vault.change_master_password("new").unwrap();
    let after = vault.to_bytes().unwrap();

    let open = |bytes: &[u8], password: &str| {
        let password = CString::new(password).unwrap();
        let mut handle: *mut VaultHandle = ptr::null_mut();
        let code = unsafe {
            vault_ffi_vault_open_password(
                bytes.as_ptr(),
                bytes.len(),
                password.as_ptr(),
                &mut handle,
            )
        };
        assert_eq!(code, OK);
        handle
    };
    let merge = |handle, bytes: &[u8]| unsafe {
        vault_ffi_merge_remote(handle, bytes.as_ptr(), bytes.len())
    };

    let stale = open(&before, "old");
    assert_eq!(merge(stale, &after), ERR_PASSWORD_CHANGED);
    let current = open(&after, "new");
    assert_eq!(merge(current, &before), OK);
    unsafe {
        vault_ffi_vault_free(stale);
        vault_ffi_vault_free(current);
    }
}

/// Tiny verifier so the test asserts real cryptographic validity of the
/// FFI output, using vault-core's public-key derivation.
mod p256_check {
    pub fn verify(private_key: &[u8], msg: &[u8], der_sig: &[u8]) -> bool {
        let Ok(pub_sec1) = vault_core::passkey::public_key_sec1(private_key) else {
            return false;
        };
        // Re-verify via vault-core by re-deriving; a mismatch means invalid.
        // vault-core has no public verify fn, so re-sign a fresh assertion
        // is not equal; instead we trust the sec1 derivation + p256 here.
        use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
        let Ok(vk) = VerifyingKey::from_sec1_bytes(&pub_sec1) else {
            return false;
        };
        let Ok(sig) = Signature::from_der(der_sig) else {
            return false;
        };
        vk.verify(msg, &sig).is_ok()
    }
}
