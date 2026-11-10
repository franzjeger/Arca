//! Passkey FFI surface: stateless ES256 authenticator operations and atomic
//! vault-backed passkey registration, enumeration, and assertion by item id.

use std::os::raw::c_char;
use std::panic::catch_unwind;
use std::slice;

use vault_core::{Error, VaultItem};

use crate::{
    cstr, emit, guard_result, lock_vault, reserialize_verified, VaultHandle, ERR_LOCKED,
    ERR_NULL_ARG, ERR_OP_FAILED, ERR_PANIC, ERR_UTF8, OK,
};

/// Create a new passkey for `rp_id`. On `OK`, the three out-pairs are heap
/// buffers to free with [`crate::vault_ffi_free`]: the credential id, the
/// P-256 private key (SEC1, 32 bytes — store it encrypted!), and the CBOR
/// attestation object.
///
/// # Safety
/// All pointers must be valid; `rp_id` a NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_passkey_create(
    rp_id: *const c_char,
    user_verified: bool,
    out_credential_id: *mut *mut u8,
    out_credential_id_len: *mut usize,
    out_private_key: *mut *mut u8,
    out_private_key_len: *mut usize,
    out_attestation_object: *mut *mut u8,
    out_attestation_object_len: *mut usize,
) -> i32 {
    if out_credential_id.is_null()
        || out_credential_id_len.is_null()
        || out_private_key.is_null()
        || out_private_key_len.is_null()
        || out_attestation_object.is_null()
        || out_attestation_object_len.is_null()
    {
        return ERR_NULL_ARG;
    }
    let Some(rp_id) = cstr(rp_id) else {
        return ERR_UTF8;
    };
    match catch_unwind(|| vault_core::passkey::create(rp_id, user_verified)) {
        Ok(Ok(pk)) => {
            emit(pk.credential_id, out_credential_id, out_credential_id_len);
            emit(
                pk.private_key.to_vec(),
                out_private_key,
                out_private_key_len,
            );
            emit(
                pk.attestation_object,
                out_attestation_object,
                out_attestation_object_len,
            );
            OK
        }
        Ok(Err(_)) => ERR_OP_FAILED,
        Err(_) => ERR_PANIC,
    }
}

/// Create a new passkey for `rp_id` AND store it in the vault, returning the new
/// vault bytes to persist plus the credential id and CBOR attestation object to
/// hand back to the relying party.
///
/// This is `vault_ffi_passkey_create` followed by the store, in one call,
/// because the two must not come apart. On iOS the AutoFill extension writes the
/// SHARED App Group vault file directly — there is no separate desktop app to
/// route the store through, the way the browser flow does — so if creation and
/// storage were two FFI calls, a failure between them would hand the relying
/// party a credential whose private key never reached the vault: a passkey that
/// can register but can never sign in again. Here the private key is in the
/// returned vault bytes before the credential id is emitted.
///
/// `user_handle` is opaque bytes (may be non-UTF-8), so it crosses as a pointer
/// and length, not a C string. Registration adds a new credential, retaining
/// existing keys even for the same account: the relying party may reject or
/// cancel this ceremony after we return. Exclusions are checked by the caller.
///
/// # Safety
/// All non-null pointers must be valid; `rp_id` and `user_name` NUL-terminated
/// C strings; `user_handle` a buffer of `user_handle_len` bytes (or null with
/// length 0). The four out-pairs receive heap buffers to free with
/// [`crate::vault_ffi_free`].
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn vault_ffi_passkey_register(
    handle: *mut VaultHandle,
    rp_id: *const c_char,
    user_name: *const c_char,
    user_handle: *const u8,
    user_handle_len: usize,
    user_verified: bool,
    now_unix_millis: i64,
    out_vault_bytes: *mut *mut u8,
    out_vault_bytes_len: *mut usize,
    out_credential_id: *mut *mut u8,
    out_credential_id_len: *mut usize,
    out_attestation_object: *mut *mut u8,
    out_attestation_object_len: *mut usize,
) -> i32 {
    if handle.is_null()
        || rp_id.is_null()
        || user_name.is_null()
        || out_vault_bytes.is_null()
        || out_vault_bytes_len.is_null()
        || out_credential_id.is_null()
        || out_credential_id_len.is_null()
        || out_attestation_object.is_null()
        || out_attestation_object_len.is_null()
    {
        return ERR_NULL_ARG;
    }
    *out_vault_bytes = std::ptr::null_mut();
    *out_vault_bytes_len = 0;
    *out_credential_id = std::ptr::null_mut();
    *out_credential_id_len = 0;
    *out_attestation_object = std::ptr::null_mut();
    *out_attestation_object_len = 0;

    let (Some(rp_id), Some(user_name)) = (cstr(rp_id), cstr(user_name)) else {
        return ERR_UTF8;
    };
    let user_handle: Vec<u8> = if user_handle.is_null() || user_handle_len == 0 {
        Vec::new()
    } else {
        std::slice::from_raw_parts(user_handle, user_handle_len).to_vec()
    };

    let mut vault = match lock_vault(&(*handle).vault) {
        Ok(v) => v,
        Err(code) => return code,
    };
    if !vault.is_unlocked() {
        return ERR_LOCKED;
    }

    // Create first so a creation failure never touches the vault.
    let new_pk = match guard_result(|| vault_core::passkey::create(rp_id, user_verified)) {
        Ok(pk) => pk,
        Err(code) => return code,
    };
    let credential_id = new_pk.credential_id.clone();
    let attestation_object = new_pk.attestation_object.clone();

    let item = vault_core::Item::new(
        VaultItem::Passkey {
            title: rp_id.to_string(),
            rp_id: rp_id.to_string(),
            user_name: user_name.to_string(),
            user_handle,
            credential_id: new_pk.credential_id.clone(),
            private_key: new_pk.private_key.to_vec(),
            sign_count: 0,
        },
        now_unix_millis,
    );
    let item_id = item.id;

    let result = guard_result(|| {
        vault.upsert_item(item)?;
        reserialize_verified(&vault, None)
    });

    match result {
        Ok(bytes) => {
            emit(bytes, out_vault_bytes, out_vault_bytes_len);
            emit(credential_id, out_credential_id, out_credential_id_len);
            emit(
                attestation_object,
                out_attestation_object,
                out_attestation_object_len,
            );
            OK
        }
        Err(code) => {
            // Undo the newly inserted item without having cloned the entire vault.
            let _ = vault.rollback_item(item_id, None);
            code
        }
    }
}

/// Produce an assertion. On `OK`, the two out-pairs are heap buffers to free:
/// `authenticatorData` and the DER ES256 signature. The signature counter is
/// always 0 (synced credential), so there is nothing to persist.
///
/// # Safety
/// All pointers must be valid; slices described by (ptr, len) must be readable.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn vault_ffi_passkey_assert(
    private_key: *const u8,
    private_key_len: usize,
    rp_id: *const c_char,
    user_verified: bool,
    client_data_hash: *const u8,
    client_data_hash_len: usize,
    out_authenticator_data: *mut *mut u8,
    out_authenticator_data_len: *mut usize,
    out_signature: *mut *mut u8,
    out_signature_len: *mut usize,
) -> i32 {
    if private_key.is_null()
        || client_data_hash.is_null()
        || out_authenticator_data.is_null()
        || out_authenticator_data_len.is_null()
        || out_signature.is_null()
        || out_signature_len.is_null()
    {
        return ERR_NULL_ARG;
    }
    let Some(rp_id) = cstr(rp_id) else {
        return ERR_UTF8;
    };
    let key = slice::from_raw_parts(private_key, private_key_len);
    let hash = slice::from_raw_parts(client_data_hash, client_data_hash_len);
    match catch_unwind(|| vault_core::passkey::assert(key, rp_id, hash, user_verified)) {
        Ok(Ok((auth_data, sig))) => {
            emit(
                auth_data,
                out_authenticator_data,
                out_authenticator_data_len,
            );
            emit(sig, out_signature, out_signature_len);
            OK
        }
        Ok(Err(_)) => ERR_OP_FAILED,
        Err(_) => ERR_PANIC,
    }
}

/// Every passkey in the vault, as the metadata iOS' credential store needs:
/// `[{ id, rp_id, user_name, user_handle, credential_id }]`, binary fields
/// base64. NOT secret — this is what a relying party already knows about the
/// credential. The private key stays behind the handle; see
/// [`vault_ffi_passkey_assert_for_id`].
///
/// Separate from `vault_ffi_identities` for the same reason that one is
/// logins-only: each feeds a differently-shaped platform store, and a merged
/// list would make both callers filter out the other's entries.
///
/// # Safety
/// `handle` valid; out pointers writable.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_passkey_identities(
    handle: *mut VaultHandle,
    out_json: *mut *mut u8,
    out_json_len: *mut usize,
) -> i32 {
    if handle.is_null() || out_json.is_null() || out_json_len.is_null() {
        return ERR_NULL_ARG;
    }
    let vault = match lock_vault(&(*handle).vault) {
        Ok(v) => v,
        Err(code) => return code,
    };
    match guard_result(|| {
        let b64 = data_encoding::BASE64;
        let mut rows: Vec<serde_json::Value> = Vec::new();
        for item in vault.active_items()? {
            if let VaultItem::Passkey {
                rp_id,
                user_name,
                user_handle,
                credential_id,
                ..
            } = &item.data
            {
                rows.push(serde_json::json!({
                    "id": item.id.to_string(),
                    "rp_id": rp_id,
                    "user_name": user_name,
                    "user_handle": b64.encode(user_handle),
                    "credential_id": b64.encode(credential_id),
                }));
            }
        }
        Ok(serde_json::to_string(&rows).expect("json"))
    }) {
        Ok(json) => {
            emit(json.into_bytes(), out_json, out_json_len);
            OK
        }
        Err(code) => code,
    }
}

/// A WebAuthn assertion from a stored passkey, by item id.
///
/// This exists so a client that HOLDS the vault never sees the private key.
/// The older [`vault_ffi_passkey_assert`] takes the key as an argument because
/// the macOS extension receives it from the app process; on a phone the
/// extension owns the handle, and exporting the key to Swift just to pass it
/// back in would put the one secret that must not leak into the one runtime
/// that cannot wipe it.
///
/// On OK: `{ credential_id, user_handle, authenticator_data, signature }`,
/// base64. `ERR_NOT_FOUND` if the id is unknown or not a passkey.
///
/// # Safety
/// `handle` valid; `id_utf8` NUL-terminated; the hash slice readable; out
/// pointers writable.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_passkey_assert_for_id(
    handle: *mut VaultHandle,
    id_utf8: *const c_char,
    client_data_hash: *const u8,
    client_data_hash_len: usize,
    user_verified: i32,
    out_json: *mut *mut u8,
    out_json_len: *mut usize,
) -> i32 {
    if handle.is_null()
        || client_data_hash.is_null()
        || out_json.is_null()
        || out_json_len.is_null()
    {
        return ERR_NULL_ARG;
    }
    let Some(id) = cstr(id_utf8) else {
        return ERR_UTF8;
    };
    let hash = slice::from_raw_parts(client_data_hash, client_data_hash_len);
    let vault = match lock_vault(&(*handle).vault) {
        Ok(v) => v,
        Err(code) => return code,
    };
    match guard_result(|| {
        let uuid = uuid::Uuid::parse_str(id).map_err(|_| Error::NotFound)?;
        let item = vault.get_item(uuid).map_err(|_| Error::NotFound)?;
        let VaultItem::Passkey {
            rp_id,
            user_handle,
            credential_id,
            private_key,
            ..
        } = &item.data
        else {
            return Err(Error::NotFound);
        };
        let (auth_data, signature) =
            vault_core::passkey::assert(private_key, rp_id, hash, user_verified != 0)?;
        let b64 = data_encoding::BASE64;
        Ok(serde_json::to_string(&serde_json::json!({
            "credential_id": b64.encode(credential_id),
            "user_handle": b64.encode(user_handle),
            "authenticator_data": b64.encode(&auth_data),
            "signature": b64.encode(&signature),
        }))
        .expect("json"))
    }) {
        Ok(json) => {
            emit(json.into_bytes(), out_json, out_json_len);
            OK
        }
        Err(code) => code,
    }
}
