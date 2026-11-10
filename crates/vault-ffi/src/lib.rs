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
//! unwinding across the C boundary. That needs `panic = "unwind"`, which the
//! `release-ffi` profile provides and the check below enforces.
//!
//! SECURITY: returned buffers may contain secrets (a passkey private key, or a
//! password). The caller must copy them into the platform credential / encrypted
//! vault and free them promptly; [`vault_ffi_free`] zeroes them. Error codes
//! never leak key material or plaintext.

#[cfg(panic = "abort")]
compile_error!(
    "vault-ffi needs panic = \"unwind\" or its catch_unwind guards are dead: \
     build with `--profile release-ffi`"
);

use std::os::raw::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::slice;
use std::sync::{Arc, Mutex, MutexGuard};

use serde::Serialize;
use vault_core::{host_of, Error, ItemKind, SymmetricKey, Vault, VaultItem, KEY_LEN};

pub mod passkey;
pub mod sync;
pub mod write;

pub use passkey::*;
pub use write::*;

#[cfg(test)]
mod tests;

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
///
/// v17: NULL `notes` in `vault_ffi_upsert_login` and `vault_ffi_upsert_wifi`
/// keeps the item's notes. Before, it erased them (Wi-Fi refused NULL), and
/// iOS, which never shows a login's notes, wiped them on every edit. Adds
/// `vault_ffi_vault_check`, so an import can refuse a file that is not a vault.
///
/// v18: a master password change gives the vault a new key. The sync status
/// gains `needsPassword`, `vault_ffi_sync_adopt_password` takes a change made
/// on another device on, and two codes are new: `ERR_PASSWORD_CHANGED` for a
/// file sealed after a change this vault has not taken on, and
/// `ERR_DIFFERENT_VAULT` for a password that opens a file that is not this
/// vault's. A merge skips a copy sealed before a change instead of failing.
///
/// v19 adds `vault_ffi_vault_load`, a handle to a vault that is not open yet,
/// so a phone that is still locked can sync, find a master password changed on
/// another device, and open with that password alone.
///
/// v20: every copy says how often each device has pushed it. Adds
/// `vault_ffi_sync_set_device` (this device's id and name),
/// `vault_ffi_sync_acknowledge_rollback`, `vault_ffi_devices`, and `rolledBack`
/// in the sync status: devices whose latest changes the remote had lost.
///
/// v21: a device that knows of a master password change keeps the copy that
/// carries it, and refuses the old password and quick unlock until it takes
/// the change on. Adds `vault_ffi_sync_rotated_copy` (the copy sync found),
/// `vault_ffi_vault_adopt` (take the change on from a kept copy, locked and
/// offline) and `vault_ffi_vault_key_epoch` (to tell a kept copy the vault has
/// since caught up with).
///
/// v22: duplicate logins, reviewed before they are merged. Adds
/// `vault_ffi_find_duplicates` (what a review shows, no secret) and
/// `vault_ffi_merge_duplicates` (the groups chosen, only while every login
/// shown is unchanged; [`ERR_CHANGED`] when one is not).
pub const ABI_VERSION: i32 = 22;

// Return codes.
pub(crate) const OK: i32 = 0;
pub(crate) const ERR_NULL_ARG: i32 = -1;
pub(crate) const ERR_UTF8: i32 = -2;
pub(crate) const ERR_OP_FAILED: i32 = -3;
pub(crate) const ERR_LOCKED: i32 = -4;
pub(crate) const ERR_NOT_FOUND: i32 = -5;
pub(crate) const ERR_PANIC: i32 = -6;
pub(crate) const ERR_DECRYPT: i32 = -7;
pub(crate) const ERR_BAD_KEY_LEN: i32 = -8;
// -9 (ERR_SYNC_FAILED) is defined by the sync surface.
pub(crate) const ERR_PASSWORD_CHANGED: i32 = -10;
pub(crate) const ERR_DIFFERENT_VAULT: i32 = -11;
/// Items a choice was made about changed after they were shown.
pub(crate) const ERR_CHANGED: i32 = -12;

/// Map a core error to a stable return code (never leaks detail).
pub(crate) fn err_code(e: &Error) -> i32 {
    match e {
        Error::Locked => ERR_LOCKED,
        Error::NotFound => ERR_NOT_FOUND,
        Error::Decryption => ERR_DECRYPT,
        // An id of another kind is, to a caller editing one kind, not found.
        Error::WrongKind => ERR_NOT_FOUND,
        Error::KeyRotated => ERR_PASSWORD_CHANGED,
        Error::DifferentVault => ERR_DIFFERENT_VAULT,
        Error::Changed => ERR_CHANGED,
        _ => ERR_OP_FAILED,
    }
}

/// Merge another copy of this vault, where one sealed before a master password
/// change counts as merged: nothing in it can be trusted, and whoever wrote it
/// re-sends its edits once it has the new password (`Vault::merge_remote`).
fn merge_copy(vault: &mut Vault, bytes: &[u8]) -> vault_core::Result<()> {
    match vault.merge_remote(bytes) {
        Err(Error::StaleKey) => Ok(()),
        merged => merged,
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
        return OK; // nothing on disk yet
    }
    let remote = std::slice::from_raw_parts(remote_bytes, remote_len);
    let mut vault = match lock_vault(&(*handle).vault) {
        Ok(v) => v,
        Err(code) => return code,
    };
    if !vault.is_unlocked() {
        return ERR_LOCKED;
    }
    match guard_result(|| merge_copy(&mut vault, remote)) {
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
        if let Err(code) = guard_result(|| merge_copy(&mut vault, remote)) {
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
/// handle sees them. The `Arc` also makes [`sync::vault_ffi_sync_new`] outlive
/// its vault handle safely — freeing the handle mid-sync drops one reference,
/// not the vault.
pub struct VaultHandle {
    pub(crate) vault: Arc<Mutex<Vault>>,
}

impl VaultHandle {
    /// A second owner of this handle's vault, for the sync surface. Safe in
    /// itself — the unsafety is in getting a `&VaultHandle` from the caller's
    /// raw pointer, which happens at the entry point.
    pub(crate) fn share_vault(&self) -> Arc<Mutex<Vault>> {
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
pub(crate) fn lock_vault(vault: &Mutex<Vault>) -> Result<MutexGuard<'_, Vault>, i32> {
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

/// Whether `vault_bytes` is a vault this build can open: a container it knows,
/// that parses, from a version no newer than its own. Needs no key and reads
/// nothing secret, so a client can refuse a mis-picked file before it replaces
/// the only copy of a vault (ABI v17). `OK`, or the error opening would give.
///
/// # Safety
/// `vault_bytes` must point to a readable buffer of `vault_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_vault_check(vault_bytes: *const u8, vault_len: usize) -> i32 {
    if vault_bytes.is_null() {
        return ERR_NULL_ARG;
    }
    let bytes = std::slice::from_raw_parts(vault_bytes, vault_len);
    match guard_result(|| Vault::from_bytes(bytes).map(drop)) {
        Ok(()) => OK,
        Err(code) => code,
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
    let device = SymmetricKey::from_slice(&mut key_arr);

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

/// Load a vault from its raw file bytes WITHOUT opening it (ABI v19).
///
/// Nothing can be read through the handle until something opens it, and only
/// one thing does: [`sync::vault_ffi_sync_adopt_password`], which takes on a
/// master password changed on another device. That is what this is for. A
/// phone that is locked cannot learn of the change any other way, because the
/// sync engine that finds it needs a handle to run over; with this one, the
/// new password alone opens the vault. Every read on a handle that is still
/// locked returns `ERR_LOCKED`.
///
/// # Safety
/// `vault_bytes` must point to a readable buffer of `vault_len` bytes;
/// `out_handle` must be a valid writable pointer.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_vault_load(
    vault_bytes: *const u8,
    vault_len: usize,
    out_handle: *mut *mut VaultHandle,
) -> i32 {
    if vault_bytes.is_null() || out_handle.is_null() {
        return ERR_NULL_ARG;
    }
    *out_handle = std::ptr::null_mut();
    let bytes = slice::from_raw_parts(vault_bytes, vault_len);
    match guard_result(|| Vault::from_bytes(bytes)) {
        Ok(vault) => {
            *out_handle = Box::into_raw(Box::new(VaultHandle {
                vault: Arc::new(Mutex::new(vault)),
            }));
            OK
        }
        Err(code) => code,
    }
}

/// Take on a master password change made on another device from `copy`, a copy
/// of this vault sealed after the change that the caller kept when sync found
/// it (ABI v21). Works on a handle that is not open yet
/// ([`vault_ffi_vault_load`]) and leaves it open under the new key; writing the
/// vault is the caller's (`vault_ffi_merge_and_serialize`). Needs no network.
///
/// Returns `OK`; `ERR_DECRYPT` when `password` does not open the copy;
/// `ERR_DIFFERENT_VAULT` when it opens one that is not this vault's (a
/// different vault, or one forged by someone who knew an old password); and
/// `ERR_NOT_FOUND` when this vault already has that change or a later one.
///
/// # Safety
/// `handle` must be valid; `copy` must point to `copy_len` readable bytes;
/// `password` must be a NUL-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_vault_adopt(
    handle: *mut VaultHandle,
    copy: *const u8,
    copy_len: usize,
    password: *const c_char,
) -> i32 {
    if handle.is_null() || copy.is_null() || password.is_null() {
        return ERR_NULL_ARG;
    }
    let Some(password) = cstr(password) else {
        return ERR_UTF8;
    };
    let copy = slice::from_raw_parts(copy, copy_len);
    let handle = &*handle;
    let mut vault = match lock_vault(&handle.vault) {
        Ok(v) => v,
        Err(code) => return code,
    };
    let adopted = guard_result(|| match vault.adopt_rotation(copy, password) {
        // Caught up another way since the copy was kept.
        Err(Error::StaleKey) => Err(Error::NotFound),
        adopted => adopted,
    });
    match adopted {
        Ok(()) => OK,
        Err(code) => code,
    }
}

/// The key epoch a vault file's header names (ABI v21): how many master
/// password changes the vault had been through when that copy was sealed.
/// Read without a key, so unauthenticated: for telling whether a copy the
/// caller kept is still ahead of its vault, never for trusting either.
///
/// # Safety
/// `vault_bytes` must point to `vault_len` readable bytes; `out_epoch` must be
/// a valid writable pointer.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_vault_key_epoch(
    vault_bytes: *const u8,
    vault_len: usize,
    out_epoch: *mut u64,
) -> i32 {
    if vault_bytes.is_null() || out_epoch.is_null() {
        return ERR_NULL_ARG;
    }
    let bytes = slice::from_raw_parts(vault_bytes, vault_len);
    match guard_result(|| Vault::from_bytes(bytes).map(|v| v.header().key_epoch)) {
        Ok(epoch) => {
            *out_epoch = epoch;
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

/// The devices that push this vault (ABI v20), as a UTF-8 JSON array:
/// `[{"id","name","uploads","lastUpload"}, ...]`, `lastUpload` in Unix ms by
/// that device's clock. `ERR_LOCKED` until the vault is open. Free the buffer
/// with [`vault_ffi_free`].
///
/// # Safety
/// `handle` must be valid; `out_json`/`out_json_len` writable pointers.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_devices(
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
    let listed = guard_result(|| {
        let devices: Vec<_> = vault
            .devices()?
            .iter()
            .map(|d| {
                serde_json::json!({
                    "id": d.id.to_string(),
                    "name": d.name,
                    "uploads": d.uploads,
                    "lastUpload": d.last_upload,
                })
            })
            .collect();
        serde_json::to_vec(&devices).map_err(|_| Error::Serialization)
    });
    match listed {
        Ok(json) => {
            emit(json, out_json, out_json_len);
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

/// Run a fallible closure inside a panic guard, flattening the core error to a
/// return code. `Ok(value)` on success, `Err(code)` on error or panic.
pub(crate) fn guard_result<T>(f: impl FnOnce() -> vault_core::Result<T>) -> Result<T, i32> {
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
pub(crate) fn reserialize_verified(
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
