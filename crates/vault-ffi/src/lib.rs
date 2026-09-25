//! C ABI over `vault-core` for native platform integrations.
//!
//! Consumed by the AutoFill Credential Provider extensions (Swift) on macOS and
//! iOS. Three surfaces, all returning freshly-allocated buffers the caller frees
//! with [`vault_ffi_free`]:
//!
//! * **Passkeys (v1)** — stateless ES256 authenticator ops
//!   (`vault_ffi_passkey_create` / `_assert`). The caller already holds the
//!   private key; see `docs/PASSKEYS.md`.
//! * **Passwords (v2, v3)** — a stateful vault surface (`vault_ffi_vault_open`,
//!   `_vault_open_password` + `_identities` / `_password_for_id` /
//!   `_vault_free`). Swift can't run Argon2id/XChaCha20, so it hands over the
//!   encrypted file bytes (from the shared App Group container) and either the
//!   device key (from the shared keychain) or the master password; the unlocked
//!   vault lives behind an opaque [`VaultHandle`] here.
//! * **Device unlock (v4)** — `vault_ffi_enable_device_unlock` /
//!   `_disable_device_unlock` / `_has_device_unlock`, so a client that opened
//!   with the password can mint its own quick-unlock key. The only surface that
//!   produces a **new vault file**; it still performs no I/O, the bytes come
//!   back for the caller to persist.
//! * **Sync (v5)** — [`mod@sync`]: the pull→merge→push cycle from
//!   [`vault_sync`], so a client can reach the user's encrypted vault in their
//!   own Drive instead of being handed a file. This is the one surface that
//!   **does** perform I/O, and only network I/O: it talks to Google, never to
//!   the filesystem. Merged vault bytes still come back for the caller to
//!   persist.
//!
//! No file or clock access here — [`vault_core`] is I/O-free and this is a thin
//! wrapper over it. Network access is confined to the sync surface.
//!
//! Every entry point is wrapped so a panic becomes an error code instead of
//! unwinding across the C boundary.
//!
//! SECURITY: returned buffers may contain secrets (a passkey private key, or a
//! password). The caller must copy them into the platform credential / encrypted
//! vault and free them promptly; [`vault_ffi_free`] zeroes them. Error codes
//! never leak key material or plaintext.

use std::os::raw::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::slice;
use std::sync::{Arc, Mutex, MutexGuard};

use serde::Serialize;
use vault_core::{host_of, Error, ItemKind, SymmetricKey, Vault, VaultItem, KEY_LEN};

pub mod sync;

/// ABI version. Bump on any breaking change to a signature below.
///
/// v2 adds the stateful passwords surface (`vault_ffi_vault_open`,
/// `vault_ffi_identities`, `vault_ffi_password_for_id`, `vault_ffi_vault_free`)
/// used by the macOS AutoFill credential provider.
///
/// v3 adds `vault_ffi_vault_open_password`, so a client with no device key
/// (a phone on first launch) can open the vault at all. Purely additive.
///
/// v4 adds the device-unlock surface (`vault_ffi_enable_device_unlock`,
/// `vault_ffi_disable_device_unlock`, `vault_ffi_has_device_unlock`), so a
/// client that opened with the master password can mint its own quick-unlock
/// key instead of waiting for some other process to do it. This is the first
/// operation that produces a **new vault file**, though it still writes
/// nothing: the bytes come back for the caller to persist. Purely additive.
///
/// v5 adds the sync surface (see [`mod@sync`]). Purely additive to the C
/// signatures, but it changes two things a client may have relied on, which is
/// why it is a version bump rather than a silent extension:
///
/// * the vault behind a [`VaultHandle`] is now internally synchronized, so
///   calls on one handle from several threads no longer need external locking
///   (the restriction on `vault_ffi_vault_free` is unchanged);
/// * a handle's contents can now change underneath the caller, because a sync
///   merges a peer's items into the very vault the handle exposes.
///
/// v16 adds encrypted per-item password history and prepared password restores.
pub const ABI_VERSION: i32 = 16;

// Return codes.
pub(crate) const OK: i32 = 0;
pub(crate) const ERR_NULL_ARG: i32 = -1;
pub(crate) const ERR_UTF8: i32 = -2;
pub(crate) const ERR_OP_FAILED: i32 = -3;
const ERR_LOCKED: i32 = -4;
const ERR_NOT_FOUND: i32 = -5;
pub(crate) const ERR_PANIC: i32 = -6;
const ERR_DECRYPT: i32 = -7;
const ERR_BAD_KEY_LEN: i32 = -8;
// -9 (ERR_SYNC_FAILED) is defined by the sync surface.

/// Map a core error to a stable return code (never leaks detail).
fn err_code(e: &Error) -> i32 {
    match e {
        Error::Locked => ERR_LOCKED,
        Error::NotFound => ERR_NOT_FOUND,
        Error::Decryption => ERR_DECRYPT,
        _ => ERR_OP_FAILED,
    }
}

#[no_mangle]
pub extern "C" fn vault_ffi_abi_version() -> i32 {
    ABI_VERSION
}

/// Move a `Vec<u8>` into a caller-owned buffer via the out-pointers. The caller
/// must release it with [`vault_ffi_free`].
///
/// # Safety
/// `out_ptr` and `out_len` must be valid, writable pointers.
pub(crate) unsafe fn emit(buf: Vec<u8>, out_ptr: *mut *mut u8, out_len: *mut usize) {
    // An empty result would otherwise hand back a non-null dangling pointer
    // (Box::as_mut_ptr of a zero-length slice), which a caller keying off
    // `ptr != null` could dereference. Return an unambiguous (null, 0) instead.
    if buf.is_empty() {
        *out_ptr = std::ptr::null_mut();
        *out_len = 0;
        return;
    }
    let mut boxed = buf.into_boxed_slice();
    *out_len = boxed.len();
    *out_ptr = boxed.as_mut_ptr();
    std::mem::forget(boxed);
}

/// Free a buffer returned by this library, zeroing it first.
///
/// # Safety
/// `ptr`/`len` must be a pair previously produced by this library (or `ptr`
/// null). Passing any other pointer is undefined behavior.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_free(ptr: *mut u8, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    let mut boxed = Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, len));
    for b in boxed.iter_mut() {
        *b = 0;
    }
    drop(boxed);
}

/// Read a NUL-terminated UTF-8 C string into a `&str`.
///
/// # Safety
/// `s` must be a valid NUL-terminated C string or null.
pub(crate) unsafe fn cstr<'a>(s: *const c_char) -> Option<&'a str> {
    if s.is_null() {
        return None;
    }
    std::ffi::CStr::from_ptr(s).to_str().ok()
}

/// Create a new passkey for `rp_id`. On `OK`, the three out-pairs are heap
/// buffers to free with [`vault_ffi_free`]: the credential id, the P-256 private
/// key (SEC1, 32 bytes — store it encrypted!), and the CBOR attestation object.
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
/// [`vault_ffi_free`].
#[no_mangle]
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

    // Roll back the complete handle if serialization fails.
    let previous = vault.clone();

    let result = guard_result(|| {
        let item = vault_core::Item::new(
            VaultItem::Passkey {
                title: rp_id.to_string(),
                rp_id: rp_id.to_string(),
                user_name: user_name.to_string(),
                user_handle: user_handle.clone(),
                credential_id: new_pk.credential_id.clone(),
                private_key: new_pk.private_key.to_vec(),
                sign_count: 0,
            },
            now_unix_millis,
        );
        vault.upsert_item(item)?;
        let bytes = reserialize_verified(&vault, None)?;
        Ok(bytes)
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
            // Undo the in-memory change so the handle matches the last file we
            // wrote (which is none, on this path).
            *vault = previous;
            code
        }
    }
}

/// Fold another copy of THIS vault (from disk) into the in-memory handle.
///
/// WHY THIS EXISTS. The app and the AutoFill extension are separate processes
/// that both write the one shared vault file, each from its own decrypted
/// in-memory copy. Whoever writes second used to serialize its stale copy over
/// the first's committed change and silently lose it — a login the app just
/// saved, or a passkey the extension just registered. Calling this before a
/// write folds the on-disk state in first, so a write ADDS to the other side's
/// work instead of erasing it.
///
/// It is the SAME union/newest-wins merge sync uses (`Vault::merge_remote`), so
/// a passkey and a login committed on either side both survive. A remote that
/// is a DIFFERENT vault fails to decrypt and returns `ERR_DECRYPT` rather than
/// importing anything — the caller must then refuse the write, not clobber.
///
/// A null/empty remote is "nothing on disk yet" and succeeds as a no-op.
///
/// # Safety
/// `handle` must be a valid, unlocked handle; `remote_bytes` a buffer of
/// `remote_len` bytes (or null with len 0).
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_merge_remote(
    handle: *mut VaultHandle,
    remote_bytes: *const u8,
    remote_len: usize,
) -> i32 {
    if handle.is_null() {
        return ERR_NULL_ARG;
    }
    if remote_bytes.is_null() || remote_len == 0 {
        return OK; // nothing on disk to fold in
    }
    let remote = std::slice::from_raw_parts(remote_bytes, remote_len);
    let mut vault = match lock_vault(&(*handle).vault) {
        Ok(v) => v,
        Err(code) => return code,
    };
    if !vault.is_unlocked() {
        return ERR_LOCKED;
    }
    match guard_result(|| vault.merge_remote(remote)) {
        Ok(()) => OK,
        Err(code) => code,
    }
}

/// Fold the on-disk vault into the handle and hand back the bytes to write.
///
/// [`vault_ffi_merge_remote`] merges but returns nothing, so a caller that
/// wanted "merge what is on disk, then persist the result" had to obtain its
/// bytes from some *earlier* call — and on the sync path those bytes were
/// serialized before a whole network round-trip. Anything another process wrote
/// during that window was silently overwritten: on Apple, the app's sync cycle
/// erasing a passkey the AutoFill extension had just registered. This does both
/// halves in one call, so a caller holding the vault lock can merge and write
/// without a gap in between.
///
/// `remote_bytes` may be null/empty (no file on disk yet), which merges nothing
/// and just serializes. The returned buffer is verified re-openable before it
/// is handed back, and must be freed with [`vault_ffi_free`].
///
/// # Safety
/// `handle` must be valid; the (ptr, len) slice must be readable; both
/// out-pointers must be writable.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_merge_and_serialize(
    handle: *mut VaultHandle,
    remote_bytes: *const u8,
    remote_len: usize,
    out_vault_bytes: *mut *mut u8,
    out_vault_bytes_len: *mut usize,
) -> i32 {
    if handle.is_null() || out_vault_bytes.is_null() || out_vault_bytes_len.is_null() {
        return ERR_NULL_ARG;
    }
    *out_vault_bytes = std::ptr::null_mut();
    *out_vault_bytes_len = 0;

    let mut vault = match lock_vault(&(*handle).vault) {
        Ok(v) => v,
        Err(code) => return code,
    };
    if !vault.is_unlocked() {
        return ERR_LOCKED;
    }
    // A merge that fails must abort the write rather than let the caller
    // persist a vault that never saw what is on disk.
    if !remote_bytes.is_null() && remote_len > 0 {
        let remote = std::slice::from_raw_parts(remote_bytes, remote_len);
        if let Err(code) = guard_result(|| vault.merge_remote(remote)) {
            return code;
        }
    }
    match guard_result(|| reserialize_verified(&vault, None)) {
        Ok(bytes) => {
            emit(bytes, out_vault_bytes, out_vault_bytes_len);
            OK
        }
        Err(code) => code,
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

// ===========================================================================
// Passwords surface (ABI v2) — for the macOS AutoFill credential provider.
//
// Vault open/unlock happens here (Swift can't do Argon2id/XChaCha20). Swift
// reads the encrypted vault file from the shared App Group container and a
// device key from the shared keychain, passes both in, and gets back login
// identities (metadata) and, on selection, a single password.
// ===========================================================================

/// Opaque handle to an unlocked vault. Created by [`vault_ffi_vault_open`],
/// released (locked + zeroized) by [`vault_ffi_vault_free`].
///
/// The vault is behind an `Arc<Mutex<_>>` so the sync surface (v5) can hold the
/// *same* vault this handle exposes. Sharing it is the point: a cycle merges a
/// peer's changes into this vault, and the next `vault_ffi_identities` on this
/// handle sees them. The `Arc` also makes [`vault_ffi_sync_new`] outlive its
/// vault handle safely — freeing the handle mid-sync drops one reference, not
/// the vault.
pub struct VaultHandle {
    vault: Arc<Mutex<Vault>>,
}

impl VaultHandle {
    /// A second owner of this handle's vault, for the sync surface. Safe in
    /// itself — the unsafety is in getting a `&VaultHandle` from the caller's
    /// raw pointer, which happens at the entry point.
    fn share_vault(&self) -> Arc<Mutex<Vault>> {
        self.vault.clone()
    }
}

/// Borrow the vault, treating a poisoned lock as a failure rather than
/// recovering from it.
///
/// Poisoning means an earlier call panicked while holding the lock, and
/// `Vault::merge_remote` takes the item list out before putting the merged one
/// back — so a panic mid-merge can leave the vault holding *no items*. The
/// panic guard already turned that into an error code for whoever hit it;
/// silently handing the emptied vault to the next caller is how it would become
/// an empty vault serialized over the user's file, or pushed to their Drive.
fn lock_vault(vault: &Mutex<Vault>) -> Result<MutexGuard<'_, Vault>, i32> {
    vault.lock().map_err(|_| ERR_OP_FAILED)
}

/// One login identity as handed to Swift: metadata only, never a secret.
#[derive(Serialize)]
struct Identity {
    id: String,
    user: String,
    domain: String,
    label: String,
}

/// One item of ANY kind, for the app's list. Metadata only, never a secret.
///
/// Separate from [`Identity`] on purpose. `vault_ffi_identities` feeds the
/// platform credential store, which must stay logins-only — a Wi-Fi password is
/// not something a browser can fill, and publishing one would put nonsense in
/// the QuickType bar. This is the app's own view, and it shows everything.
#[derive(Serialize)]
struct ItemMeta {
    id: String,
    /// "login" | "passkey" | "ssh_key" | "wifi" | "secure_note"
    kind: String,
    title: String,
    subtitle: String,
    url: String,
    has_totp: bool,
}

fn kind_name(kind: ItemKind) -> &'static str {
    match kind {
        ItemKind::Login => "login",
        ItemKind::Passkey => "passkey",
        ItemKind::SshKey => "ssh_key",
        ItemKind::Wifi => "wifi",
        ItemKind::SecureNote => "secure_note",
        ItemKind::Bookmark => "bookmark",
        // Written by a newer build than this one. Shown rather than hidden: an
        // entry the user cannot see is an entry they think they lost.
        ItemKind::Unknown => "unknown",
    }
}

/// Every active item, whatever its kind.
fn items_json(vault: &Vault) -> vault_core::Result<String> {
    let items: Vec<ItemMeta> = vault
        .list_items(false)?
        .into_iter()
        .map(|s| ItemMeta {
            id: s.id.to_string(),
            kind: kind_name(s.kind).to_string(),
            title: s.title,
            subtitle: s.subtitle,
            url: s.url,
            has_totp: s.has_totp,
        })
        .collect();
    serde_json::to_string(&items).map_err(|_| Error::Serialization)
}

/// The full decrypted payload of one item, tagged by kind.
///
/// SECRET, all of it: this is the private SSH key, the Wi-Fi password, the note
/// body. Every variant carries what that kind actually holds rather than a
/// lowest common denominator, so the UI never has to guess which fields mean
/// something.
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ItemDetail {
    Login {
        title: String,
        username: String,
        password: String,
        url: String,
        has_totp: bool,
        notes: String,
    },
    Passkey {
        title: String,
        rp_id: String,
        user_name: String,
    },
    SshKey {
        title: String,
        comment: String,
        key_type: String,
        /// OpenSSH one-liner, the form you paste into authorized_keys.
        public_key: String,
        fingerprint: String,
    },
    Wifi {
        title: String,
        ssid: String,
        password: String,
        security: String,
        hidden: bool,
        notes: String,
    },
    SecureNote {
        title: String,
        body: String,
    },
    /// An entry from a newer build. Nothing of it can be read here, so the UI
    /// is told exactly that rather than being handed empty fields.
    Unknown {
        title: String,
        stored_kind: String,
    },
    Bookmark {
        title: String,
        url: String,
        folder: String,
        notes: String,
    },
}

fn item_detail_json(vault: &Vault, id_str: &str) -> vault_core::Result<String> {
    let id = uuid::Uuid::parse_str(id_str).map_err(|_| Error::NotFound)?;
    let item = vault.get_item(id)?;
    // Matched by REFERENCE and cloned: `VaultItem` zeroizes on drop, so moving
    // a field out of it would take the secret with it and leave nothing to
    // wipe. The clones are short-lived and die with the JSON buffer, which
    // `vault_ffi_free` zeroizes.
    let detail = match &item.data {
        VaultItem::Login {
            title,
            username,
            password,
            url,
            totp_secret,
            notes,
        } => ItemDetail::Login {
            title: title.clone(),
            username: username.clone(),
            password: password.clone(),
            url: url.clone(),
            // The SECRET never crosses; only whether a code can be asked for.
            has_totp: totp_secret.as_ref().is_some_and(|s| !s.is_empty()),
            notes: notes.clone(),
        },
        VaultItem::Passkey {
            title,
            rp_id,
            user_name,
            ..
        } => ItemDetail::Passkey {
            title: title.clone(),
            rp_id: rp_id.clone(),
            user_name: user_name.clone(),
        },
        VaultItem::SshKey {
            title,
            comment,
            key_type,
            public_key,
            fingerprint,
            ..
        } => ItemDetail::SshKey {
            title: title.clone(),
            comment: comment.clone(),
            key_type: key_type.clone(),
            // The PRIVATE key deliberately does not cross. A phone cannot use
            // it — there is no ssh-agent here — so sending it would be pure
            // exposure for a value nothing on this side can spend.
            //
            // Formatted by vault-core rather than assembled here: the
            // authorized_keys line has a wire format, and two places building
            // it their own way is how they drift.
            public_key: vault_core::ssh::authorized_key_from_blob(public_key, comment)
                .unwrap_or_default(),
            fingerprint: fingerprint.clone(),
        },
        VaultItem::Wifi {
            title,
            ssid,
            password,
            security,
            hidden,
            notes,
        } => ItemDetail::Wifi {
            title: title.clone(),
            ssid: ssid.clone(),
            password: password.clone(),
            security: security.clone(),
            hidden: *hidden,
            notes: notes.clone(),
        },
        VaultItem::SecureNote { title, body } => ItemDetail::SecureNote {
            title: title.clone(),
            body: body.clone(),
        },
        VaultItem::Bookmark {
            title,
            url,
            folder,
            notes,
        } => ItemDetail::Bookmark {
            title: title.clone(),
            url: url.clone(),
            folder: folder.clone(),
            notes: notes.clone(),
        },
        VaultItem::Unknown(u) => ItemDetail::Unknown {
            title: u.kind.clone(),
            stored_kind: u.kind.clone(),
        },
    };
    serde_json::to_string(&detail).map_err(|_| Error::Serialization)
}

/// The live TOTP code for a login, with how long it stays valid.
fn totp_json(vault: &Vault, id_str: &str) -> vault_core::Result<String> {
    let id = uuid::Uuid::parse_str(id_str).map_err(|_| Error::NotFound)?;
    let secret = match &vault.get_item(id)?.data {
        VaultItem::Login {
            totp_secret: Some(s),
            ..
        } if !s.is_empty() => s.clone(),
        _ => return Err(Error::NotFound),
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::Serialization)?
        .as_secs();
    let code = vault_core::current_totp(&secret, now)?;
    serde_json::to_string(&serde_json::json!({
        "code": code.code,
        "period": code.period,
        "remaining": code.remaining,
    }))
    .map_err(|_| Error::Serialization)
}

/// Build the JSON identity array from the unlocked vault's active logins.
fn identities_json(vault: &Vault) -> vault_core::Result<String> {
    let ids: Vec<Identity> = vault
        .list_items(false)?
        .into_iter()
        .filter(|s| s.kind == ItemKind::Login)
        .map(|s| Identity {
            id: s.id.to_string(),
            user: s.subtitle,
            domain: host_of(&s.url),
            label: s.title,
        })
        .collect();
    serde_json::to_string(&ids).map_err(|_| Error::Serialization)
}

/// Fetch the password bytes for a login item by its id string.
fn password_for(vault: &Vault, id_str: &str) -> vault_core::Result<Vec<u8>> {
    let id = uuid::Uuid::parse_str(id_str).map_err(|_| Error::NotFound)?;
    match &vault.get_item(id)?.data {
        VaultItem::Login { password, .. } => Ok(password.as_bytes().to_vec()),
        _ => Err(Error::NotFound),
    }
}

/// Open + unlock a vault from its raw file bytes using a device key (the 32-byte
/// quick-unlock key from the shared keychain). On `OK`, `*out_handle` is a handle
/// to free with [`vault_ffi_vault_free`]. Errors: `ERR_BAD_KEY_LEN` (wrong key
/// size), `ERR_DECRYPT` (wrong key / not a device-unlock vault / tampered),
/// `ERR_OP_FAILED` (unrecognized format).
///
/// # Safety
/// `vault_bytes`/`device_key` must point to readable buffers of the given
/// lengths; `out_handle` must be a valid writable pointer.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_vault_open(
    vault_bytes: *const u8,
    vault_len: usize,
    device_key: *const u8,
    device_key_len: usize,
    out_handle: *mut *mut VaultHandle,
) -> i32 {
    if vault_bytes.is_null() || device_key.is_null() || out_handle.is_null() {
        return ERR_NULL_ARG;
    }
    // Pre-null the out-handle so a caller that inspects it without checking the
    // return code never sees a stale/uninitialized pointer on an error path.
    *out_handle = std::ptr::null_mut();
    if device_key_len != KEY_LEN {
        return ERR_BAD_KEY_LEN;
    }
    let bytes = slice::from_raw_parts(vault_bytes, vault_len);
    let mut key_arr = zeroize::Zeroizing::new([0u8; KEY_LEN]);
    key_arr.copy_from_slice(slice::from_raw_parts(device_key, device_key_len));
    let device = SymmetricKey::from_bytes(*key_arr);

    let opened = guard_result(|| {
        let mut vault = Vault::from_bytes(bytes)?;
        vault.unlock_with_device_key(&device)?;
        Ok(vault)
    });
    match opened {
        Ok(vault) => {
            *out_handle = Box::into_raw(Box::new(VaultHandle {
                vault: Arc::new(Mutex::new(vault)),
            }));
            OK
        }
        Err(code) => code,
    }
}

/// Open + unlock a vault from its raw file bytes using the **master password**.
///
/// [`vault_ffi_vault_open`] needs a device key that some *other* process must
/// already have minted into the keychain. A fresh client — a phone on first
/// launch, a recovery tool — has no such key and could otherwise never open the
/// vault at all. This is the entry point that makes the FFI usable on its own.
///
/// `password` is a NUL-terminated UTF-8 C string. Deriving the key runs Argon2id
/// with the parameters stored in the vault header, so this deliberately takes
/// hundreds of milliseconds; call it off the UI thread. Errors: `ERR_DECRYPT`
/// (wrong password or tampered file), `ERR_OP_FAILED` (unrecognized format or
/// non-UTF-8 password).
///
/// # Safety
/// `vault_bytes` must point to a readable buffer of `vault_len`; `password` must
/// be a valid NUL-terminated string; `out_handle` must be a valid writable
/// pointer.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_vault_open_password(
    vault_bytes: *const u8,
    vault_len: usize,
    password: *const c_char,
    out_handle: *mut *mut VaultHandle,
) -> i32 {
    if vault_bytes.is_null() || password.is_null() || out_handle.is_null() {
        return ERR_NULL_ARG;
    }
    *out_handle = std::ptr::null_mut();
    let bytes = slice::from_raw_parts(vault_bytes, vault_len);
    let Some(password) = cstr(password) else {
        return ERR_OP_FAILED;
    };

    let opened = guard_result(|| {
        let mut vault = Vault::from_bytes(bytes)?;
        vault.unlock(password)?;
        Ok(vault)
    });
    match opened {
        Ok(vault) => {
            *out_handle = Box::into_raw(Box::new(VaultHandle {
                vault: Arc::new(Mutex::new(vault)),
            }));
            OK
        }
        Err(code) => code,
    }
}

/// Lock + free a handle (zeroizes the vault key and all decrypted items).
/// Passing null is a no-op.
///
/// # Safety
/// `handle` must be a handle from [`vault_ffi_vault_open`] (or null), freed once.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_vault_free(handle: *mut VaultHandle) {
    if handle.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let boxed = Box::from_raw(handle);
        // Poison recovery is right *here* and nowhere else: the vault is being
        // destroyed, so re-sealing an inconsistent one still zeroizes the key
        // and the plaintext items, which is the whole job. Refusing would leave
        // secrets resident until the process exits.
        if let Ok(mut vault) = boxed.vault.lock().or_else(|e| Ok::<_, ()>(e.into_inner())) {
            let _ = vault.lock(); // Vault::lock — re-seal + zeroize
        }
        drop(boxed);
    }));
}

/// All login identities as a UTF-8 JSON array (metadata only, never a secret):
/// `[{"id","user","domain","label"}, ...]`. On `OK`, `*out_json` is a buffer to
/// free with [`vault_ffi_free`].
///
/// # Safety
/// `handle` must be valid; `out_json`/`out_json_len` writable pointers.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_identities(
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
    match guard_result(|| identities_json(&vault)) {
        Ok(json) => {
            emit(json.into_bytes(), out_json, out_json_len);
            OK
        }
        Err(code) => code,
    }
}

/// Every active item, of every kind, as JSON. Metadata only, never a secret.
///
/// Distinct from [`vault_ffi_identities`], which stays logins-only because it
/// feeds the platform credential store. This is what an app's own list should
/// call: before it existed, four of the five item kinds were invisible on iOS.
///
/// Free the buffer with [`vault_ffi_free`].
///
/// # Safety
/// `handle` must be valid; `out_json`/`out_json_len` writable pointers.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_items(
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
    match guard_result(|| items_json(&vault)) {
        Ok(json) => {
            emit(json.into_bytes(), out_json, out_json_len);
            OK
        }
        Err(code) => code,
    }
}

/// The full payload of one item, tagged by kind, as JSON.
///
/// SECRET: this carries the Wi-Fi password and the note body in the clear. The
/// buffer is zeroized by [`vault_ffi_free`]; do not retain it.
///
/// One thing deliberately does NOT cross: an SSH item's PRIVATE key. There is no
/// ssh-agent on a phone, so nothing on that side can spend it, and shipping it
/// would be exposure bought for nothing. The public key and fingerprint do come,
/// because those are what you actually need to read off a screen.
///
/// # Safety
/// `handle` valid; `id_utf8` a NUL-terminated C string; out pointers writable.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_item_detail(
    handle: *mut VaultHandle,
    id_utf8: *const c_char,
    out_json: *mut *mut u8,
    out_json_len: *mut usize,
) -> i32 {
    if handle.is_null() || id_utf8.is_null() || out_json.is_null() || out_json_len.is_null() {
        return ERR_NULL_ARG;
    }
    let Some(id) = cstr(id_utf8) else {
        return ERR_UTF8;
    };
    let vault = match lock_vault(&(*handle).vault) {
        Ok(v) => v,
        Err(code) => return code,
    };
    match guard_result(|| item_detail_json(&vault, id)) {
        Ok(json) => {
            emit(json.into_bytes(), out_json, out_json_len);
            OK
        }
        Err(code) => code,
    }
}

/// The live TOTP code for a login: `{ code, period, remaining }`.
///
/// SECRET-adjacent: the code is short-lived but is a second factor while it
/// lasts. The TOTP *secret* never crosses this boundary — only the derived code
/// does, so a caller that leaks one leaks thirty seconds rather than forever.
///
/// `ERR_NOT_FOUND` when the id is unknown, is not a login, or has no TOTP set.
///
/// # Safety
/// `handle` valid; `id_utf8` a NUL-terminated C string; out pointers writable.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_totp(
    handle: *mut VaultHandle,
    id_utf8: *const c_char,
    out_json: *mut *mut u8,
    out_json_len: *mut usize,
) -> i32 {
    if handle.is_null() || id_utf8.is_null() || out_json.is_null() || out_json_len.is_null() {
        return ERR_NULL_ARG;
    }
    let Some(id) = cstr(id_utf8) else {
        return ERR_UTF8;
    };
    let vault = match lock_vault(&(*handle).vault) {
        Ok(v) => v,
        Err(code) => return code,
    };
    match guard_result(|| totp_json(&vault, id)) {
        Ok(json) => {
            emit(json.into_bytes(), out_json, out_json_len);
            OK
        }
        Err(code) => code,
    }
}

/// The password for one identity id (the `id` from [`vault_ffi_identities`]).
/// SECRET: the returned buffer is zeroized by [`vault_ffi_free`]; the caller must
/// copy it into the platform credential and not retain it. `ERR_NOT_FOUND` if the
/// id is unknown or not a login.
///
/// # Safety
/// `handle` valid; `id_utf8` a NUL-terminated C string; out pointers writable.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_password_for_id(
    handle: *mut VaultHandle,
    id_utf8: *const c_char,
    out_password: *mut *mut u8,
    out_password_len: *mut usize,
) -> i32 {
    if handle.is_null() || out_password.is_null() || out_password_len.is_null() {
        return ERR_NULL_ARG;
    }
    let Some(id) = cstr(id_utf8) else {
        return ERR_UTF8;
    };
    let vault = match lock_vault(&(*handle).vault) {
        Ok(v) => v,
        Err(code) => return code,
    };
    match guard_result(|| password_for(&vault, id)) {
        Ok(pw) => {
            emit(pw, out_password, out_password_len);
            OK
        }
        Err(code) => code,
    }
}

/// Password history metadata only, newest first.
/// # Safety
/// Handle valid, id a NUL-terminated string, output pointers writable.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_password_history(
    handle: *mut VaultHandle,
    id_utf8: *const c_char,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    if handle.is_null() || id_utf8.is_null() || out.is_null() || out_len.is_null() {
        return ERR_NULL_ARG;
    }
    let Some(id) = cstr(id_utf8) else {
        return ERR_UTF8;
    };
    let vault = match lock_vault(&(*handle).vault) {
        Ok(v) => v,
        Err(code) => return code,
    };
    match guard_result(|| {
        let id = uuid::Uuid::parse_str(id).map_err(|_| Error::NotFound)?;
        let item = vault.get_item(id)?;
        let entries: Vec<_> = item
            .password_history
            .iter()
            .map(|entry| {
                serde_json::json!({
                    "id": entry.id.to_string(), "replacedAt": entry.replaced_at,
                })
            })
            .collect();
        serde_json::to_vec(&entries).map_err(|_| Error::Serialization)
    }) {
        Ok(bytes) => {
            emit(bytes, out, out_len);
            OK
        }
        Err(code) => code,
    }
}

/// Fetch one previous password. SECRET; free the buffer with vault_ffi_free.
/// # Safety
/// Handle valid, strings NUL-terminated, output pointers writable.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_history_password(
    handle: *mut VaultHandle,
    id_utf8: *const c_char,
    revision_utf8: *const c_char,
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
    let vault = match lock_vault(&(*handle).vault) {
        Ok(v) => v,
        Err(code) => return code,
    };
    match guard_result(|| {
        let id = uuid::Uuid::parse_str(id).map_err(|_| Error::NotFound)?;
        let revision = uuid::Uuid::parse_str(revision).map_err(|_| Error::NotFound)?;
        let item = vault.get_item(id)?;
        let entry = item
            .password_history
            .iter()
            .find(|h| h.id == revision)
            .ok_or(Error::NotFound)?;
        Ok(entry.password.as_bytes().to_vec())
    }) {
        Ok(bytes) => {
            emit(bytes, out, out_len);
            OK
        }
        Err(code) => code,
    }
}

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
    let vault = match lock_vault(&(*handle).vault) {
        Ok(v) => v,
        Err(code) => return code,
    };
    match guard_result(|| {
        let id = uuid::Uuid::parse_str(id).map_err(|_| Error::NotFound)?;
        let revision = uuid::Uuid::parse_str(revision).map_err(|_| Error::NotFound)?;
        let mut candidate = vault.clone();
        candidate.restore_password(id, revision, now_millis)?;
        candidate.to_bytes()
    }) {
        Ok(bytes) => {
            emit(bytes, out, out_len);
            OK
        }
        Err(code) => code,
    }
}

/// Generate a password. SECRET: the returned buffer is zeroized by
/// [`vault_ffi_free`].
///
/// Takes no vault handle, because generating a password has nothing to do with
/// an open vault — you want one while creating the account, which is before
/// there is anything to save it to. `ERR_INVALID` for a zero length or for all
/// four classes switched off, rather than quietly substituting a default: a
/// caller that asked for no digits and got digits has been lied to.
///
/// The flags are separate ints rather than a bitmask so the call site says
/// which class it means. A `1` in the wrong bit position is a bug you find in
/// production; a wrong argument name is one the compiler can help with.
///
/// # Safety
/// Out pointers must be writable.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_generate_password(
    length: usize,
    lowercase: i32,
    uppercase: i32,
    digits: i32,
    symbols: i32,
    out_password: *mut *mut u8,
    out_password_len: *mut usize,
) -> i32 {
    if out_password.is_null() || out_password_len.is_null() {
        return ERR_NULL_ARG;
    }
    let opts = vault_core::password::PasswordOptions {
        length,
        lowercase: lowercase != 0,
        uppercase: uppercase != 0,
        digits: digits != 0,
        symbols: symbols != 0,
    };
    match guard_result(|| {
        // `Zeroizing<String>` wipes on drop at the end of this closure; the copy
        // handed out is wiped by `vault_ffi_free`. Neither is left to the GC.
        vault_core::password::generate_password(&opts).map(|pw| pw.as_bytes().to_vec())
    }) {
        Ok(pw) => {
            emit(pw, out_password, out_password_len);
            OK
        }
        Err(code) => code,
    }
}

/// Generate a password that satisfies a site's Password Rules string.
///
/// `rules_utf8` is Apple's Password Rules format, which arrives from two places
/// and is the same string in both: iOS hands it to an AutoFill extension with a
/// generate request, and HTML password fields carry it in a `passwordrules`
/// attribute. An empty or unparseable string yields a strong default rather
/// than an error — it comes from arbitrary websites, and refusing to help
/// because a site wrote nonsense just sends the user back to inventing one.
///
/// SECRET: the returned buffer is zeroized by [`vault_ffi_free`].
///
/// # Safety
/// `rules_utf8` a NUL-terminated C string; out pointers writable.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_generate_password_for_rules(
    rules_utf8: *const c_char,
    default_length: usize,
    out_password: *mut *mut u8,
    out_password_len: *mut usize,
) -> i32 {
    if out_password.is_null() || out_password_len.is_null() {
        return ERR_NULL_ARG;
    }
    let Some(rules) = cstr(rules_utf8) else {
        return ERR_UTF8;
    };
    let length = if default_length == 0 {
        20
    } else {
        default_length
    };
    match guard_result(|| {
        let opts = vault_core::password::options_from_rules(rules, length);
        vault_core::password::generate_password(&opts).map(|pw| pw.as_bytes().to_vec())
    }) {
        Ok(pw) => {
            emit(pw, out_password, out_password_len);
            OK
        }
        Err(code) => code,
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
        // Summaries first, full item only for the passkeys: `get_item` clones
        // the payload (VaultItem is Drop/zeroize), and most vaults are almost
        // entirely logins that would be cloned for nothing.
        let mut rows: Vec<serde_json::Value> = Vec::new();
        for summary in vault.list_items(false)? {
            if summary.kind != vault_core::ItemKind::Passkey {
                continue;
            }
            let item = vault.get_item(summary.id)?;
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

/// Run a fallible closure inside a panic guard, flattening the core error to a
/// return code. `Ok(value)` on success, `Err(code)` on error or panic.
fn guard_result<T>(f: impl FnOnce() -> vault_core::Result<T>) -> Result<T, i32> {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(err_code(&e)),
        Err(_) => Err(ERR_PANIC),
    }
}

// ===========================================================================
// Device-unlock surface (ABI v4)
//
// Until now the FFI could only *use* a device key some other process had
// minted. On a phone there is no other process, so quick unlock was impossible
// and every AutoFill cost the user their master password and an Argon2id
// derivation. These let a client that opened with the password mint its own.
//
// Still no I/O: `vault-core` is I/O-free and this stays a thin wrapper, so the
// new file bytes come back for the caller to persist. The caller owns the
// atomic write, the backup, and the ordering.
// ===========================================================================

/// Re-serialize the handle's vault, verifying it can be reopened with
/// `check_key` before handing the bytes back.
///
/// Cheap insurance on the only path that produces a replacement vault file: the
/// caller is about to overwrite the user's only copy, so bytes that do not open
/// must never leave this function. `None` skips the device-key check (nothing to
/// check against once device unlock has been removed).
fn reserialize_verified(
    vault: &Vault,
    check_key: Option<&SymmetricKey>,
) -> vault_core::Result<Vec<u8>> {
    let bytes = vault.to_bytes()?;
    let mut probe = Vault::from_bytes(&bytes)?;
    // With no key to check against, parsing IS the check: `disable` only clears
    // a header field, and the master-password wrapped key is untouched either
    // way.
    if let Some(key) = check_key {
        probe.unlock_with_device_key(key)?;
    }
    Ok(bytes)
}

/// Turn on quick unlock. Mints a fresh 32-byte device key, wraps the vault key
/// with it, and returns **both** the key and the new vault file bytes.
///
/// The master password keeps working: this only adds a second wrapping of the
/// same vault key, it does not replace the first.
///
/// SECRET: `*out_device_key` is the quick-unlock key. Put it straight into the
/// platform keychain behind a biometric access control and free it with
/// [`vault_ffi_free`], which zeroes it. Anyone holding it can open the vault
/// without the master password — that is the entire point of it.
///
/// The handle is updated in place, so it now reports `has_device_unlock`. If the
/// caller then fails to persist the bytes, memory and file disagree until the
/// next open; nothing is lost, because the file is simply the older one.
///
/// # Safety
/// `handle` must be valid; all four out-pointers must be writable.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_enable_device_unlock(
    handle: *mut VaultHandle,
    out_device_key: *mut *mut u8,
    out_device_key_len: *mut usize,
    out_vault_bytes: *mut *mut u8,
    out_vault_bytes_len: *mut usize,
) -> i32 {
    if handle.is_null()
        || out_device_key.is_null()
        || out_device_key_len.is_null()
        || out_vault_bytes.is_null()
        || out_vault_bytes_len.is_null()
    {
        return ERR_NULL_ARG;
    }
    // Pre-null both out-pairs so an error path never leaves a caller holding a
    // stale pointer it might free or read.
    *out_device_key = std::ptr::null_mut();
    *out_device_key_len = 0;
    *out_vault_bytes = std::ptr::null_mut();
    *out_vault_bytes_len = 0;

    let mut vault = match lock_vault(&(*handle).vault) {
        Ok(v) => v,
        Err(code) => return code,
    };
    if !vault.is_unlocked() {
        return ERR_LOCKED;
    }
    let was_enabled = vault.has_device_unlock();

    let result = guard_result(|| {
        let device = SymmetricKey::generate()?;
        vault.enable_device_unlock(&device)?;
        let bytes = reserialize_verified(&vault, Some(&device))?;
        Ok((device, bytes))
    });
    match result {
        Ok((device, bytes)) => {
            emit(
                device.as_bytes().to_vec(),
                out_device_key,
                out_device_key_len,
            );
            emit(bytes, out_vault_bytes, out_vault_bytes_len);
            OK
        }
        Err(code) => {
            // The header may already carry the new wrapping. If there was
            // nothing there before, putting it back is exact. If quick unlock
            // was already on we cannot restore the OLD blob — `vault-core`
            // exposes no setter for it — so the handle keeps a key that was
            // never persisted. Harmless but stale: free the handle and reopen.
            if !was_enabled {
                let _ = vault.disable_device_unlock();
            }
            code
        }
    }
}

/// Turn quick unlock off: drop the device-wrapped key from the header and
/// return the new vault file bytes. The master password is unaffected.
///
/// Deleting the key from the keychain is not enough on its own — the wrapping
/// would stay in the file and travel to every device the vault syncs to.
///
/// # Safety
/// `handle` must be valid; both out-pointers must be writable.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_disable_device_unlock(
    handle: *mut VaultHandle,
    out_vault_bytes: *mut *mut u8,
    out_vault_bytes_len: *mut usize,
) -> i32 {
    if handle.is_null() || out_vault_bytes.is_null() || out_vault_bytes_len.is_null() {
        return ERR_NULL_ARG;
    }
    *out_vault_bytes = std::ptr::null_mut();
    *out_vault_bytes_len = 0;

    let mut vault = match lock_vault(&(*handle).vault) {
        Ok(v) => v,
        Err(code) => return code,
    };
    if !vault.is_unlocked() {
        return ERR_LOCKED;
    }

    match guard_result(|| {
        vault.disable_device_unlock()?;
        reserialize_verified(&vault, None)
    }) {
        Ok(bytes) => {
            emit(bytes, out_vault_bytes, out_vault_bytes_len);
            OK
        }
        Err(code) => code,
    }
}

/// `1` if the vault carries a device-wrapped key, `0` if not, negative on error.
///
/// The keychain can hold a key for a vault that no longer accepts it (restored
/// from a backup, say), so a client that trusts the keychain alone will prompt
/// for a biometric and then fail. Ask the vault.
///
/// # Safety
/// `handle` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_has_device_unlock(handle: *mut VaultHandle) -> i32 {
    if handle.is_null() {
        return ERR_NULL_ARG;
    }
    let vault = match lock_vault(&(*handle).vault) {
        Ok(v) => v,
        Err(code) => return code,
    };
    match catch_unwind(AssertUnwindSafe(|| vault.has_device_unlock())) {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(_) => ERR_PANIC,
    }
}

// ---- writes ---------------------------------------------------------------
//
// Everything above this point reads. A client that can only read is a viewer,
// not a password manager: it cannot save the login you just created on your
// phone. These two calls close that.
//
// They follow the same contract as the device-unlock surface: mutate the
// in-memory vault, then hand back **new vault file bytes** for the caller to
// persist. `vault-core` is I/O-free and this stays a thin wrapper, so writing
// the file (and syncing it) remains the platform's job — on iOS that is an App
// Group container the extension also reads.
//
// The handle is left consistent with what is returned: on success the caller
// holds bytes matching the handle, and on failure the item change is rolled
// back so the handle never drifts from the last persisted state.

/// Insert or update a login, returning the new vault bytes and the item id.
///
/// `id` selects an existing item to overwrite; pass NULL or "" to create one.
/// `totp_secret` and `notes` may be NULL (treated as absent/empty). Timestamps
/// come from the caller because `vault-core` has no clock: pass milliseconds
/// since the Unix epoch.
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
    if handle.is_null()
        || title.is_null()
        || username.is_null()
        || password.is_null()
        || url.is_null()
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

    // Optional strings: NULL means "not provided", which is distinct from "".
    let (Some(title), Some(username), Some(password), Some(url)) =
        (cstr(title), cstr(username), cstr(password), cstr(url))
    else {
        return ERR_UTF8;
    };
    let notes = if notes.is_null() {
        ""
    } else {
        match cstr(notes) {
            Some(s) => s,
            None => return ERR_UTF8,
        }
    };
    // v11 gave the null/empty distinction meaning instead of discarding it:
    //
    //   null  -> KEEP the existing secret (edit did not touch the field)
    //   ""    -> CLEAR it (the user removed the code)
    //   value -> set it; otpauth:// URIs are normalized to their Base32 secret
    //
    // Before this, every edit from a client that did not round-trip the secret
    // rewrote the login with totp_secret: None — so renaming a login on the
    // phone silently destroyed its verification code. The detail surface
    // deliberately never hands the secret out, which means "send back what you
    // got" was never possible; keep-on-null is the only semantics that works.
    enum TotpIntent {
        Keep,
        Clear,
        Set(String),
    }
    let totp_intent = if totp_secret.is_null() {
        TotpIntent::Keep
    } else {
        match cstr(totp_secret) {
            Some("") => TotpIntent::Clear,
            Some(s) if s.trim().to_ascii_lowercase().starts_with("otpauth://") => {
                // Reject a bad URI HERE, where the caller can show the QR scan
                // failed — storing it raw would surface later as a code that
                // derives garbage.
                match vault_core::parse_otpauth_uri(s.trim()) {
                    Ok(parsed) => TotpIntent::Set(parsed.secret),
                    Err(_) => return ERR_OP_FAILED,
                }
            }
            Some(s) => TotpIntent::Set(s.trim().to_string()),
            None => return ERR_UTF8,
        }
    };
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

    // Keep what we need to undo this if serialization fails, so a failed write
    // cannot leave the handle holding a change the caller never persisted.
    let previous = existing_id.and_then(|u| vault.get_item(u).ok());

    let totp = match totp_intent {
        TotpIntent::Set(s) => Some(s),
        TotpIntent::Clear => None,
        TotpIntent::Keep => previous.as_ref().and_then(|item| match &item.data {
            VaultItem::Login { totp_secret, .. } => totp_secret.clone(),
            _ => None,
        }),
    };

    let data = VaultItem::Login {
        title: title.to_string(),
        username: username.to_string(),
        password: password.to_string(),
        url: url.to_string(),
        totp_secret: totp,
        notes: notes.to_string(),
    };
    if let Some(u) = existing_id {
        if previous.is_none() {
            return ERR_NOT_FOUND;
        }
        // Editing an existing login must not resurrect a deleted one silently,
        // nor change its kind.
        if !matches!(
            previous.as_ref().map(|i| i.data.kind()),
            Some(ItemKind::Login)
        ) {
            return ERR_NOT_FOUND;
        }
        let _ = u;
    }

    let result = guard_result(|| {
        let item = match (existing_id, previous.as_ref()) {
            (Some(_), Some(old)) => {
                let mut it = old.clone();
                it.data = data;
                it.modified_at = now_unix_millis;
                it
            }
            _ => vault_core::Item::new(data, now_unix_millis),
        };
        let new_id = item.id;
        vault.upsert_item(item)?;
        let bytes = reserialize_verified(&vault, None)?;
        Ok((new_id, bytes))
    });

    match result {
        Ok((new_id, bytes)) => {
            emit(bytes, out_vault_bytes, out_vault_bytes_len);
            emit(new_id.to_string().into_bytes(), out_id, out_id_len);
            OK
        }
        Err(code) => {
            // Roll the handle back to the last persisted state.
            match previous {
                Some(old) => {
                    let _ = vault.upsert_item(old);
                }
                None => {
                    // A brand-new item may or may not have landed; if it did,
                    // remove it. We do not know its id on the failure path, so
                    // only the edit case is precisely restorable — a fresh item
                    // that failed to serialize is dropped by the next reload.
                }
            }
            code
        }
    }
}

/// The shared write path for the single-kind upserts (Wi-Fi, note).
///
/// Same contract as `vault_ffi_upsert_login`: create on null id, edit in place
/// on a valid one — refusing an id whose item is missing, deleted, or of
/// another kind — and hand the caller the new vault bytes to persist. On a
/// serialization failure the handle is rolled back to the last persisted item
/// so it never holds a change the caller could not write.
///
/// `upsert_login` keeps its own body because its TOTP keep-on-null semantics
/// need the previous item BEFORE the payload can be built; these two have no
/// such dependency and share everything else.
#[allow(clippy::too_many_arguments)] // the C out-param convention, like its callers
unsafe fn upsert_of_kind(
    handle: *mut VaultHandle,
    id: *const c_char,
    kind: ItemKind,
    data: VaultItem,
    now_unix_millis: i64,
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
    if existing_id.is_some()
        && !matches!(previous.as_ref().map(|i| i.data.kind()), Some(k) if k == kind)
    {
        return ERR_NOT_FOUND;
    }

    let result = guard_result(|| {
        let item = match (existing_id, previous.as_ref()) {
            (Some(_), Some(old)) => {
                let mut it = old.clone();
                it.data = data;
                it.modified_at = now_unix_millis;
                it
            }
            _ => vault_core::Item::new(data, now_unix_millis),
        };
        let new_id = item.id;
        vault.upsert_item(item)?;
        let bytes = reserialize_verified(&vault, None)?;
        Ok((new_id, bytes))
    });
    match result {
        Ok((new_id, bytes)) => {
            emit(bytes, out_vault_bytes, out_vault_bytes_len);
            emit(new_id.to_string().into_bytes(), out_id, out_id_len);
            OK
        }
        Err(code) => {
            if let Some(old) = previous {
                let _ = vault.upsert_item(old);
            }
            code
        }
    }
}

/// Create or edit a Wi-Fi network entry (ABI v12).
///
/// `security` is the join-QR token: "WPA", "WEP" or "nopass"; empty means WPA.
/// Same create/edit and rollback contract as `vault_ffi_upsert_login`.
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
    let (Some(title), Some(ssid), Some(password), Some(security), Some(notes)) = (
        cstr(title),
        cstr(ssid),
        cstr(password),
        cstr(security),
        cstr(notes),
    ) else {
        return ERR_UTF8;
    };
    let data = VaultItem::Wifi {
        title: title.to_string(),
        ssid: ssid.to_string(),
        password: password.to_string(),
        security: security.to_string(),
        hidden: hidden != 0,
        notes: notes.to_string(),
    };
    upsert_of_kind(
        handle,
        id,
        ItemKind::Wifi,
        data,
        now_unix_millis,
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
    let data = VaultItem::SecureNote {
        title: title.to_string(),
        body: body.to_string(),
    };
    upsert_of_kind(
        handle,
        id,
        ItemKind::SecureNote,
        data,
        now_unix_millis,
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
            let _ = vault.upsert_item(previous); // undo the soft delete
            code
        }
    }
}

#[cfg(test)]
mod tests {
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
    fn abi_version_is_16() {
        assert_eq!(vault_ffi_abi_version(), 16);
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
        let s =
            unsafe { std::str::from_utf8(slice::from_raw_parts(out, len)).unwrap() }.to_string();
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
        let s =
            unsafe { std::str::from_utf8(slice::from_raw_parts(out, len)).unwrap() }.to_string();
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

        let all: serde_json::Value =
            serde_json::from_str(&json_call(handle, vault_ffi_items)).unwrap();
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
        let all: serde_json::Value =
            serde_json::from_str(&json_call(handle, vault_ffi_items)).unwrap();

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
        let all: serde_json::Value =
            serde_json::from_str(&json_call(handle, vault_ffi_items)).unwrap();

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
            vault_ffi_enable_device_unlock(
                handle,
                &mut key,
                &mut key_len,
                &mut bytes,
                &mut bytes_len,
            )
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
        let listed = unsafe { std::str::from_utf8(slice::from_raw_parts(json, json_len)).unwrap() }
            .to_string();
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
        let new_id =
            String::from_utf8(unsafe { slice::from_raw_parts(idp, id_len) }.to_vec()).unwrap();
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
        let same =
            String::from_utf8(unsafe { slice::from_raw_parts(idp, id_len) }.to_vec()).unwrap();
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
        let rc =
            unsafe { vault_ffi_delete_item(handle, id_c.as_ptr(), 3_000, &mut db, &mut db_len) };
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
        let sources = [include_str!("lib.rs"), include_str!("sync.rs")];
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
            vault_ffi_vault_open_password(
                bytes.as_ptr(),
                bytes.len(),
                bad.as_ptr(),
                &mut bad_handle,
            )
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
        let json_str =
            unsafe { std::str::from_utf8(slice::from_raw_parts(json, json_len)).unwrap() };
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
                vault_ffi_merge_and_serialize(
                    handle,
                    disk.as_ptr(),
                    disk.len(),
                    &mut out,
                    &mut out_len,
                )
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
            unsafe {
                vault_ffi_merge_and_serialize(handle, ptr::null(), 0, &mut out2, &mut out2_len)
            },
            OK
        );
        assert!(out2_len > 0);
        unsafe { vault_ffi_free(out2, out2_len) };

        assert_eq!(
            unsafe {
                vault_ffi_merge_and_serialize(
                    ptr::null_mut(),
                    ptr::null(),
                    0,
                    &mut out2,
                    &mut out2_len,
                )
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
}
