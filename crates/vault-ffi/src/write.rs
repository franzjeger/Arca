//! Item mutation, password-history restore, and duplicate-login merge FFI
//! surface.
//!
//! All write operations follow the same contract: mutate the in-memory vault
//! and hand back verified vault file bytes for the caller to persist atomically.
//! On failure, the affected item is rolled back to its exact pre-mutation state
//! without cloning the entire unlocked vault.

use std::os::raw::c_char;
use std::slice;

use serde::Deserialize;
use vault_core::dedupe::MergeChoice;
use vault_core::{Change, Error, LoginEdit, NoteEdit, Vault, WifiEdit};

use crate::{
    cstr, emit, guard_result, lock_vault, reserialize_verified, VaultHandle, ERR_LOCKED,
    ERR_NOT_FOUND, ERR_NULL_ARG, ERR_OP_FAILED, ERR_UTF8, OK,
};

/// Prepare a restored password as encrypted bytes, WITHOUT changing the handle.
/// Persist the result atomically, then merge it into the handle. A failed disk
/// write can therefore never leave the handle ahead of durable storage.
/// # Safety
/// Handle valid, strings NUL-terminated, output pointers writable.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_restore_password_history(
    handle: *mut VaultHandle,
    id_utf8: *const c_char,
    revision_utf8: *const c_char,
    now_millis: i64,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    if handle.is_null()
        || id_utf8.is_null()
        || revision_utf8.is_null()
        || out.is_null()
        || out_len.is_null()
    {
        return ERR_NULL_ARG;
    }
    let (Some(id), Some(revision)) = (cstr(id_utf8), cstr(revision_utf8)) else {
        return ERR_UTF8;
    };
    let mut vault = match lock_vault(&(*handle).vault) {
        Ok(v) => v,
        Err(code) => return code,
    };
    match guard_result(|| {
        let id = uuid::Uuid::parse_str(id).map_err(|_| Error::NotFound)?;
        let revision = uuid::Uuid::parse_str(revision).map_err(|_| Error::NotFound)?;
        let previous = vault.get_item(id)?;
        vault.restore_password(id, revision, now_millis)?;
        let bytes = vault.to_bytes();
        let _ = vault.rollback_item(id, Some(previous));
        bytes
    }) {
        Ok(bytes) => {
            emit(bytes, out, out_len);
            OK
        }
        Err(code) => code,
    }
}

/// Insert or update a login, returning the new vault bytes and the item id.
///
/// `id` selects an existing item to overwrite; pass NULL or "" to create one.
/// `totp_secret` and `notes` follow the edit semantics of [`optional`]: NULL
/// keeps what the item has, "" clears it. Timestamps come from the caller
/// because `vault-core` has no clock: pass milliseconds since the Unix epoch.
///
/// # Safety
/// `handle` must be valid. Every non-NULL string must be a NUL-terminated
/// UTF-8 C string. All four out-pointers must be writable.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn vault_ffi_upsert_login(
    handle: *mut VaultHandle,
    id: *const c_char,
    title: *const c_char,
    username: *const c_char,
    password: *const c_char,
    url: *const c_char,
    totp_secret: *const c_char,
    notes: *const c_char,
    now_unix_millis: i64,
    out_vault_bytes: *mut *mut u8,
    out_vault_bytes_len: *mut usize,
    out_id: *mut *mut u8,
    out_id_len: *mut usize,
) -> i32 {
    if title.is_null() || username.is_null() || password.is_null() || url.is_null() {
        return ERR_NULL_ARG;
    }
    let (Some(title), Some(username), Some(password), Some(url)) =
        (cstr(title), cstr(username), cstr(password), cstr(url))
    else {
        return ERR_UTF8;
    };
    let (Ok(totp_secret), Ok(notes)) = (optional(totp_secret), optional(notes)) else {
        return ERR_UTF8;
    };
    let edit = LoginEdit {
        title: title.into(),
        username: username.into(),
        url: url.into(),
        password: Change::Set(password.into()),
        totp_secret,
        notes,
    };
    upsert(
        handle,
        id,
        |vault, id| vault.save_login(id, edit, now_unix_millis),
        out_vault_bytes,
        out_vault_bytes_len,
        out_id,
        out_id_len,
    )
}

/// An optional field of an edit: NULL leaves it as it is, anything else sets
/// it ("" clears). Clients never receive some secrets (TOTP) and do not show
/// others (a login's notes on iOS), so "send back what you got" is impossible
/// and "absent means erase" destroyed them on every edit — TOTP codes until
/// ABI v11, notes until v17. `Err` is invalid UTF-8.
unsafe fn optional(s: *const c_char) -> Result<Change<String>, ()> {
    if s.is_null() {
        return Ok(Change::Keep);
    }
    cstr(s).map(|value| Change::Set(value.into())).ok_or(())
}

/// The one write path for every upsert: create on a null id, edit in place on
/// a valid one, and hand the caller the new vault bytes to persist. What an
/// edit means is `vault_core::edit`'s business; this is the C plumbing.
///
/// Only the single affected item is snapshotted before the mutation, avoiding
/// an `O(N)` clone of every decrypted item in the vault.
unsafe fn upsert(
    handle: *mut VaultHandle,
    id: *const c_char,
    save: impl FnOnce(&mut Vault, Option<uuid::Uuid>) -> vault_core::Result<uuid::Uuid>,
    out_vault_bytes: *mut *mut u8,
    out_vault_bytes_len: *mut usize,
    out_id: *mut *mut u8,
    out_id_len: *mut usize,
) -> i32 {
    if handle.is_null()
        || out_vault_bytes.is_null()
        || out_vault_bytes_len.is_null()
        || out_id.is_null()
        || out_id_len.is_null()
    {
        return ERR_NULL_ARG;
    }
    *out_vault_bytes = std::ptr::null_mut();
    *out_vault_bytes_len = 0;
    *out_id = std::ptr::null_mut();
    *out_id_len = 0;
    let existing_id = if id.is_null() {
        None
    } else {
        match cstr(id) {
            Some("") => None,
            Some(s) => match uuid::Uuid::parse_str(s) {
                Ok(u) => Some(u),
                Err(_) => return ERR_NOT_FOUND,
            },
            None => return ERR_UTF8,
        }
    };

    let mut vault = match lock_vault(&(*handle).vault) {
        Ok(v) => v,
        Err(code) => return code,
    };
    if !vault.is_unlocked() {
        return ERR_LOCKED;
    }
    let previous = existing_id.and_then(|u| vault.get_item(u).ok());
    let mut touched_id: Option<uuid::Uuid> = None;

    match guard_result(|| {
        let new_id = save(&mut vault, existing_id)?;
        touched_id = Some(new_id);
        Ok((new_id, reserialize_verified(&vault, None)?))
    }) {
        Ok((new_id, bytes)) => {
            emit(bytes, out_vault_bytes, out_vault_bytes_len);
            emit(new_id.to_string().into_bytes(), out_id, out_id_len);
            OK
        }
        Err(code) => {
            if let Some(id) = touched_id {
                let _ = vault.rollback_item(id, previous);
            }
            code
        }
    }
}

/// Create or edit a Wi-Fi network entry (ABI v12).
///
/// `security` is the join-QR token: "WPA", "WEP" or "nopass"; empty means WPA.
/// `notes` may be NULL to keep the entry's notes (ABI v17). Same create/edit
/// contract as `vault_ffi_upsert_login`.
///
/// # Safety
/// `handle` valid; string arguments NUL-terminated or null where documented;
/// out pointers writable.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn vault_ffi_upsert_wifi(
    handle: *mut VaultHandle,
    id: *const c_char,
    title: *const c_char,
    ssid: *const c_char,
    password: *const c_char,
    security: *const c_char,
    hidden: i32,
    notes: *const c_char,
    now_unix_millis: i64,
    out_vault_bytes: *mut *mut u8,
    out_vault_bytes_len: *mut usize,
    out_id: *mut *mut u8,
    out_id_len: *mut usize,
) -> i32 {
    let (Some(title), Some(ssid), Some(password), Some(security), Ok(notes)) = (
        cstr(title),
        cstr(ssid),
        cstr(password),
        cstr(security),
        optional(notes),
    ) else {
        return ERR_UTF8;
    };
    let edit = WifiEdit {
        title: title.into(),
        ssid: ssid.into(),
        password: Change::Set(password.into()),
        security: security.into(),
        hidden: hidden != 0,
        notes,
    };
    upsert(
        handle,
        id,
        |vault, id| vault.save_wifi(id, edit, now_unix_millis),
        out_vault_bytes,
        out_vault_bytes_len,
        out_id,
        out_id_len,
    )
}

/// Create or edit a secure note (ABI v12). Same contract as the other upserts.
///
/// # Safety
/// `handle` valid; `title`/`body` NUL-terminated; out pointers writable.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn vault_ffi_upsert_secure_note(
    handle: *mut VaultHandle,
    id: *const c_char,
    title: *const c_char,
    body: *const c_char,
    now_unix_millis: i64,
    out_vault_bytes: *mut *mut u8,
    out_vault_bytes_len: *mut usize,
    out_id: *mut *mut u8,
    out_id_len: *mut usize,
) -> i32 {
    let (Some(title), Some(body)) = (cstr(title), cstr(body)) else {
        return ERR_UTF8;
    };
    let edit = NoteEdit {
        title: title.into(),
        body: body.into(),
    };
    upsert(
        handle,
        id,
        |vault, id| vault.save_note(id, edit, now_unix_millis),
        out_vault_bytes,
        out_vault_bytes_len,
        out_id,
        out_id_len,
    )
}

/// Soft-delete an item (it moves to the Trash and can be restored), returning
/// the new vault bytes.
///
/// # Safety
/// `handle` must be valid, `id` a NUL-terminated UTF-8 C string, and both
/// out-pointers writable.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_delete_item(
    handle: *mut VaultHandle,
    id: *const c_char,
    now_unix_millis: i64,
    out_vault_bytes: *mut *mut u8,
    out_vault_bytes_len: *mut usize,
) -> i32 {
    if handle.is_null()
        || id.is_null()
        || out_vault_bytes.is_null()
        || out_vault_bytes_len.is_null()
    {
        return ERR_NULL_ARG;
    }
    *out_vault_bytes = std::ptr::null_mut();
    *out_vault_bytes_len = 0;

    let Some(id_str) = cstr(id) else {
        return ERR_UTF8;
    };
    let Ok(uuid) = uuid::Uuid::parse_str(id_str) else {
        return ERR_NOT_FOUND;
    };

    let mut vault = match lock_vault(&(*handle).vault) {
        Ok(v) => v,
        Err(code) => return code,
    };
    if !vault.is_unlocked() {
        return ERR_LOCKED;
    }
    let Ok(previous) = vault.get_item(uuid) else {
        return ERR_NOT_FOUND;
    };

    match guard_result(|| {
        vault.delete_item(uuid, now_unix_millis)?;
        reserialize_verified(&vault, None)
    }) {
        Ok(bytes) => {
            emit(bytes, out_vault_bytes, out_vault_bytes_len);
            OK
        }
        Err(code) => {
            let _ = vault.rollback_item(uuid, Some(previous));
            code
        }
    }
}

/// Duplicate logins, as a review shows them, as a JSON array of groups:
/// `{"possible":bool,"keep":id,"logins":[{"id","revision","title","site",
/// "username","modifiedAt","password","hasPassword","hasTotp","hasNotes"}]}`.
/// No secret: `password` is a number that only says which logins in a group
/// share one. Changes nothing.
///
/// Free the buffer with [`crate::vault_ffi_free`].
///
/// # Safety
/// `handle` must be valid; `out_json`/`out_json_len` writable pointers.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_find_duplicates(
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
        serde_json::to_string(&vault.review_duplicate_logins()?).map_err(|_| Error::Serialization)
    }) {
        Ok(json) => {
            emit(json.into_bytes(), out_json, out_json_len);
            OK
        }
        Err(code) => code,
    }
}

#[derive(Deserialize)]
struct MergeRequest {
    choices: Vec<MergeRequestChoice>,
    shown: Vec<MergeRequestShown>,
}

#[derive(Deserialize)]
struct MergeRequestChoice {
    keep: uuid::Uuid,
    ids: Vec<uuid::Uuid>,
}

#[derive(Deserialize)]
struct MergeRequestShown {
    id: uuid::Uuid,
    revision: uuid::Uuid,
}

/// Merge the groups chosen in a review of duplicates, returning the new vault
/// bytes and how many logins went to the Trash.
///
/// `request` is UTF-8 JSON: `{"choices":[{"keep":id,"ids":[id,...]}],
/// "shown":[{"id":id,"revision":revision},...]}`, where `shown` is every login
/// the review showed, as [`vault_ffi_find_duplicates`] gave them. If one of
/// them changed since, nothing is merged and the result is [`crate::ERR_CHANGED`]:
/// show the review again.
///
/// The merge is made on a copy, which becomes the handle's vault only once its
/// bytes are written and verified, so a failure leaves the handle as it was.
///
/// # Safety
/// `handle` must be valid, `request` point to `request_len` readable bytes,
/// and the out-pointers be writable.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_merge_duplicates(
    handle: *mut VaultHandle,
    request: *const u8,
    request_len: usize,
    now_unix_millis: i64,
    out_merged: *mut usize,
    out_vault_bytes: *mut *mut u8,
    out_vault_bytes_len: *mut usize,
) -> i32 {
    if handle.is_null()
        || request.is_null()
        || out_merged.is_null()
        || out_vault_bytes.is_null()
        || out_vault_bytes_len.is_null()
    {
        return ERR_NULL_ARG;
    }
    *out_merged = 0;
    *out_vault_bytes = std::ptr::null_mut();
    *out_vault_bytes_len = 0;

    let Ok(request) =
        serde_json::from_slice::<MergeRequest>(slice::from_raw_parts(request, request_len))
    else {
        return ERR_OP_FAILED;
    };
    let choices: Vec<MergeChoice> = request
        .choices
        .into_iter()
        .map(|choice| MergeChoice {
            keep: choice.keep,
            ids: choice.ids,
        })
        .collect();
    let shown: Vec<(uuid::Uuid, uuid::Uuid)> = request
        .shown
        .iter()
        .map(|login| (login.id, login.revision))
        .collect();

    let mut vault = match lock_vault(&(*handle).vault) {
        Ok(v) => v,
        Err(code) => return code,
    };
    let mut merged_vault = vault.clone();
    match guard_result(|| {
        let merged = merged_vault.merge_logins(&choices, &shown, now_unix_millis)?;
        Ok((merged, reserialize_verified(&merged_vault, None)?))
    }) {
        Ok((merged, bytes)) => {
            *vault = merged_vault;
            *out_merged = merged;
            emit(bytes, out_vault_bytes, out_vault_bytes_len);
            OK
        }
        Err(code) => code,
    }
}
