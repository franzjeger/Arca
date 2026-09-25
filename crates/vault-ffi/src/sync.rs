//! Sync surface (ABI v5) — the pull→merge→push cycle, reachable from Swift.
//!
//! `vault-sync` had already been lifted out of the desktop app so a second
//! client could use it. This is the boundary that lets one: without it, the
//! phone's only route to a vault is AirDrop and an import screen.
//!
//! ## What crosses the boundary, and what does not
//!
//! Everything network-shaped stays in Rust. Drive's REST calls, the TLS, the
//! token refresh and the whole cycle run below this line, so Swift never sees
//! an access token and cannot get the retry policy wrong.
//!
//! Two things stay on the caller's side, both because they have no portable
//! form:
//!
//! * **The interactive sign-in.** [`vault_ffi_sync_auth_begin`] hands back a
//!   URL and keeps the PKCE verifier; the caller opens it however its platform
//!   does (`ASWebAuthenticationSession` on iOS, a loopback listener on the
//!   desktop) and returns the code to [`vault_ffi_sync_auth_finish`]. The
//!   verifier never crosses the boundary at all.
//! * **Storage.** The refresh token comes back for the caller's keychain, and
//!   merged vault bytes come back for the caller's file. `vault-core` is
//!   I/O-free and this stays a thin wrapper over it — the same rule the
//!   device-unlock surface follows.
//!
//! ## Threading
//!
//! [`vault_ffi_sync_now`] performs network I/O and blocks for as long as that
//! takes. Call it off the UI thread — on iOS an AutoFill extension that blocks
//! its main thread is killed by the watchdog, not merely slow. It is safe to
//! call concurrently with reads on the vault handle: they share one vault
//! behind a mutex, and the engine's own in-flight guard makes a second
//! concurrent cycle a no-op rather than a race.

use std::os::raw::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, Mutex};

use vault_core::Vault;
use vault_sync::drive::{arca_credentials, DriveStore, RefreshTokenStore};
use vault_sync::oauth::{OAuthClient, Pkce};
use vault_sync::{LocalError, LocalVault, RemoteStore, SilentObserver, SyncEngine};
use zeroize::Zeroizing;

use crate::{cstr, emit, VaultHandle, ERR_NULL_ARG, ERR_OP_FAILED, ERR_PANIC, ERR_UTF8, OK};

/// The cycle ran but did not finish. The reason is in the status JSON's
/// `lastError`; it is the same sentence the desktop shows in Settings.
///
/// Distinct from `ERR_OP_FAILED` because it means something different to a
/// caller: nothing is wrong with the arguments and nothing needs fixing, the
/// network or the credential just did not cooperate. Retry later.
pub(crate) const ERR_SYNC_FAILED: i32 = -9;

// ---------------------------------------------------------------------------
// The platform's side of vault-sync's traits
// ---------------------------------------------------------------------------

/// The refresh token, held in memory only.
///
/// Persisting it is the caller's job — the iOS keychain, the OS secret store —
/// so this crate keeps the copy it needs to refresh with and nothing more.
#[derive(Default)]
struct Credential {
    refresh_token: Mutex<Option<Zeroizing<String>>>,
}

impl RefreshTokenStore for Credential {
    fn exists(&self) -> bool {
        self.refresh_token
            .lock()
            .map(|t| t.is_some())
            .unwrap_or(false)
    }

    fn read(&self) -> Result<Option<Zeroizing<String>>, String> {
        self.refresh_token
            .lock()
            .map(|t| t.clone())
            .map_err(|_| "credential poisoned".to_string())
    }
}

/// The vault the caller already has open, shared with the engine.
///
/// The engine merges into *this* vault, so a `vault_ffi_identities` call on the
/// caller's handle after a sync shows the peer's changes with no reload.
struct SharedVault {
    vault: Arc<Mutex<Vault>>,
    /// Vault bytes the caller still has to write, set only when a cycle
    /// actually integrated something from the remote.
    pending: Mutex<Option<Vec<u8>>>,
}

impl LocalVault for SharedVault {
    fn merge_and_serialize(&self, remotes: &[Vec<u8>]) -> Result<Vec<u8>, LocalError> {
        // Not recovered from on purpose — see `lock_vault` in lib.rs. A merge
        // interrupted by a panic can leave the vault holding no items, and this
        // is the one path that would serialize that and push it to the user's
        // Drive.
        let mut vault = self
            .vault
            .lock()
            .map_err(|_| LocalError::Save("vault state poisoned".into()))?;
        if !vault.is_unlocked() {
            // Not an error: the engine defers and keeps the pending changes.
            return Err(LocalError::Locked);
        }
        vault_sync::merge_remotes(&mut vault, remotes)?;
        let bytes = vault
            .to_bytes()
            .map_err(|e| LocalError::Save(e.to_string()))?;

        // Only remote content changes what belongs on disk. Serializing
        // re-encrypts with fresh nonces, so bytes from a push of unchanged
        // state differ from the file while meaning exactly the same thing —
        // handing those back would rewrite the user's vault every cycle for
        // nothing.
        if !remotes.is_empty() {
            *self
                .pending
                .lock()
                .map_err(|_| LocalError::Save("pending buffer poisoned".into()))? =
                Some(bytes.clone());
        }
        Ok(bytes)
    }
}

// ---------------------------------------------------------------------------
// Handles
// ---------------------------------------------------------------------------

/// Opaque sync engine bound to one open vault. Free with
/// [`vault_ffi_sync_free`].
pub struct SyncHandle {
    engine: SyncEngine,
    credential: Arc<Credential>,
    drive: Arc<DriveStore>,
    local: Arc<SharedVault>,
}

/// An interactive sign-in in progress: the PKCE verifier and the redirect URI
/// it was bound to. Free with [`vault_ffi_sync_auth_free`].
pub struct SyncAuth {
    oauth: OAuthClient,
    pkce: Pkce,
    /// Held rather than asked for again at `finish`. The server compares the
    /// two byte for byte and rejects a mismatch with an unhelpful
    /// `invalid_grant`, so making them structurally the same value removes the
    /// commonest way an OAuth integration fails.
    redirect_uri: String,
}

/// Status as the caller's UI sees it. camelCase to match the desktop's DTO, so
/// both front ends read one shape.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct StatusJson {
    connected: bool,
    account: Option<String>,
    last_sync_unix: Option<u64>,
    /// Already phrased for a person. Carries HTTP statuses and transport
    /// failures, never a token or anything from inside the vault.
    last_error: Option<String>,
    /// Whether *this* call merged remote changes. Always false for
    /// [`vault_ffi_sync_status`], which only reports.
    merged: bool,
}

fn status_json(handle: &SyncHandle, merged: bool) -> Vec<u8> {
    let status = handle.engine.status();
    let json = StatusJson {
        connected: status.connected,
        account: status.account,
        last_sync_unix: status.last_sync_unix,
        last_error: status.last_error,
        merged,
    };
    // A status object of four scalars and two strings cannot fail to serialize;
    // an empty object still parses on the far side if it somehow did.
    serde_json::to_vec(&json).unwrap_or_else(|_| b"{}".to_vec())
}

// ---------------------------------------------------------------------------
// Engine lifecycle
// ---------------------------------------------------------------------------

/// Create a sync engine over an already-open vault.
///
/// Starts **disconnected**: call [`vault_ffi_sync_set_credential`] with a
/// refresh token before [`vault_ffi_sync_now`] will do anything. The vault
/// handle may be freed while this handle lives — they share the vault.
///
/// # Safety
/// `vault` must be a live handle from `vault_ffi_vault_open*`; `out_handle`
/// must be writable.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_sync_new(
    vault: *mut VaultHandle,
    out_handle: *mut *mut SyncHandle,
) -> i32 {
    if vault.is_null() || out_handle.is_null() {
        return ERR_NULL_ARG;
    }
    *out_handle = std::ptr::null_mut();

    let shared = (*vault).share_vault();
    let result = catch_unwind(AssertUnwindSafe(|| {
        let credential = Arc::new(Credential::default());
        let drive = Arc::new(DriveStore::new(arca_credentials(), credential.clone()));
        let local = Arc::new(SharedVault {
            vault: shared,
            pending: Mutex::new(None),
        });
        let engine = SyncEngine::new(drive.clone(), local.clone(), Arc::new(SilentObserver));
        SyncHandle {
            engine,
            credential,
            drive,
            local,
        }
    }));
    match result {
        Ok(handle) => {
            *out_handle = Box::into_raw(Box::new(handle));
            OK
        }
        Err(_) => ERR_PANIC,
    }
}

/// Free a sync handle. Passing null is a no-op.
///
/// Must not overlap another call on the same handle, and must be called once.
/// Freeing while [`vault_ffi_sync_now`] is running on another thread is a
/// use-after-free: join that thread first.
///
/// # Safety
/// `handle` must come from [`vault_ffi_sync_new`] (or be null), freed once.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_sync_free(handle: *mut SyncHandle) {
    if handle.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| drop(Box::from_raw(handle))));
}

/// Set (or clear) the credential this engine syncs with.
///
/// `refresh_token` null **disconnects**: the cached access token is dropped and
/// the account forgotten, so the next cycle is a no-op. `account` is a display
/// label for the UI and may be null.
///
/// Connecting resets the engine's bookkeeping, which matters: a remote checksum
/// recorded against one Google account means nothing under another.
///
/// # Safety
/// `handle` must be valid; the strings NUL-terminated UTF-8 or null.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_sync_set_credential(
    handle: *mut SyncHandle,
    refresh_token: *const c_char,
    account: *const c_char,
) -> i32 {
    if handle.is_null() {
        return ERR_NULL_ARG;
    }
    let token = if refresh_token.is_null() {
        None
    } else {
        match cstr(refresh_token) {
            Some(t) => Some(Zeroizing::new(t.to_string())),
            None => return ERR_UTF8,
        }
    };
    // A non-UTF-8 label is worth rejecting rather than silently dropping: it
    // means the caller passed something that is not the string it thinks.
    let label = if account.is_null() {
        None
    } else {
        match cstr(account) {
            Some(a) => Some(a.to_string()),
            None => return ERR_UTF8,
        }
    };

    let handle = &*handle;
    let connecting = token.is_some();
    match handle.credential.refresh_token.lock() {
        Ok(mut slot) => *slot = token,
        Err(_) => return ERR_OP_FAILED,
    }
    // Drop any access token minted for the previous credential.
    handle.drive.invalidate_auth();
    if connecting {
        handle.engine.set_account(label);
    } else {
        handle.engine.forget_account();
    }
    OK
}

/// Tell the engine local vault state changed and must be pushed next cycle.
///
/// # Safety
/// `handle` must be valid or null.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_sync_mark_dirty(handle: *mut SyncHandle) {
    if handle.is_null() {
        return;
    }
    (*handle).engine.mark_dirty();
}

/// Current status as UTF-8 JSON, without touching the network:
/// `{"connected","account","lastSyncUnix","lastError","merged"}`.
/// `merged` is always false here — only [`vault_ffi_sync_now`] can merge.
/// Free the buffer with `vault_ffi_free`.
///
/// # Safety
/// `handle` must be valid; the out-pointers writable.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_sync_status(
    handle: *mut SyncHandle,
    out_json: *mut *mut u8,
    out_json_len: *mut usize,
) -> i32 {
    if handle.is_null() || out_json.is_null() || out_json_len.is_null() {
        return ERR_NULL_ARG;
    }
    *out_json = std::ptr::null_mut();
    *out_json_len = 0;
    match catch_unwind(AssertUnwindSafe(|| status_json(&*handle, false))) {
        Ok(json) => {
            emit(json, out_json, out_json_len);
            OK
        }
        Err(_) => ERR_PANIC,
    }
}

/// Run one pull→merge→push cycle. **Blocking, network I/O — never on the UI
/// thread.**
///
/// `*out_status_json` is always produced (unless the arguments were bad), so a
/// failing cycle still reports why.
///
/// `*out_vault_bytes` is non-null **only when remote changes were merged**, and
/// is then the new vault file the caller must persist. Write it: the merge is
/// already live in the shared vault, so skipping the write leaves memory ahead
/// of disk until the next sync recovers it from the remote.
///
/// Bytes are handed back on failure too, when a merge happened before the
/// failure did. A cycle that merges a peer's changes and then fails to upload
/// has still changed the local vault, and that is worth keeping.
///
/// Returns `OK`, or `ERR_SYNC_FAILED` with the reason in the status JSON.
///
/// # Safety
/// `handle` must be valid; all four out-pointers writable.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_sync_now(
    handle: *mut SyncHandle,
    out_vault_bytes: *mut *mut u8,
    out_vault_bytes_len: *mut usize,
    out_status_json: *mut *mut u8,
    out_status_json_len: *mut usize,
) -> i32 {
    if handle.is_null()
        || out_vault_bytes.is_null()
        || out_vault_bytes_len.is_null()
        || out_status_json.is_null()
        || out_status_json_len.is_null()
    {
        return ERR_NULL_ARG;
    }
    *out_vault_bytes = std::ptr::null_mut();
    *out_vault_bytes_len = 0;
    *out_status_json = std::ptr::null_mut();
    *out_status_json_len = 0;

    let handle = &*handle;
    let outcome = catch_unwind(AssertUnwindSafe(|| handle.engine.sync_now()));

    // Take the merged bytes whatever happened: they describe a change already
    // made to the shared vault, so the caller needs them even on the paths that
    // report a failure.
    let pending = handle
        .local
        .pending
        .lock()
        .ok()
        .and_then(|mut slot| slot.take());
    if let Some(bytes) = pending {
        emit(bytes, out_vault_bytes, out_vault_bytes_len);
    }

    let (merged, code) = match &outcome {
        Ok(Ok(merged)) => (*merged, OK),
        Ok(Err(_)) => (false, ERR_SYNC_FAILED),
        Err(_) => (false, ERR_PANIC),
    };
    if let Ok(json) = catch_unwind(AssertUnwindSafe(|| status_json(handle, merged))) {
        emit(json, out_status_json, out_status_json_len);
    }
    code
}

// ---------------------------------------------------------------------------
// Interactive sign-in
// ---------------------------------------------------------------------------

/// Begin a sign-in: returns the authorization URL to open and a handle holding
/// the PKCE verifier until [`vault_ffi_sync_auth_finish`].
///
/// `redirect_uri` is whatever the platform can catch — a custom URL scheme on
/// iOS, `http://127.0.0.1:<port>` on the desktop. It is remembered here, so
/// `finish` cannot disagree with `begin` about it.
///
/// The URL is not a secret (it is about to be typed into a browser). The
/// verifier is, and never leaves this handle.
///
/// # Safety
/// `redirect_uri` must be a NUL-terminated C string; the out-pointers writable.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_sync_auth_begin(
    redirect_uri: *const c_char,
    out_url: *mut *mut u8,
    out_url_len: *mut usize,
    out_auth: *mut *mut SyncAuth,
) -> i32 {
    if redirect_uri.is_null() || out_url.is_null() || out_url_len.is_null() || out_auth.is_null() {
        return ERR_NULL_ARG;
    }
    *out_url = std::ptr::null_mut();
    *out_url_len = 0;
    *out_auth = std::ptr::null_mut();

    let Some(redirect) = cstr(redirect_uri) else {
        return ERR_UTF8;
    };

    let built = catch_unwind(AssertUnwindSafe(|| {
        let pkce = Pkce::generate()?;
        let oauth = OAuthClient::new(arca_credentials());
        let url = oauth.authorization_url(redirect, &pkce);
        Ok::<_, String>((url, oauth, pkce))
    }));
    match built {
        Ok(Ok((url, oauth, pkce))) => {
            *out_auth = Box::into_raw(Box::new(SyncAuth {
                oauth,
                pkce,
                redirect_uri: redirect.to_string(),
            }));
            emit(url.into_bytes(), out_url, out_url_len);
            OK
        }
        // The only failure inside is the RNG, which is not a caller mistake.
        Ok(Err(_)) => ERR_OP_FAILED,
        Err(_) => ERR_PANIC,
    }
}

/// Finish a sign-in: redeem `code` and return the refresh token plus the
/// account's email. **Blocking, network I/O.**
///
/// SECRET: `*out_refresh_token` grants access to the synced ciphertext until
/// the user revokes it. Put it straight into the platform keychain and free it
/// with `vault_ffi_free`, which zeroes it. It is the value to hand back to
/// [`vault_ffi_sync_set_credential`].
///
/// `*out_account` is a display label and may come back null — the account
/// lookup is a second request, and losing it must not fail a sign-in that
/// otherwise succeeded.
///
/// The PKCE verifier is single-use: a second call on the same handle is
/// rejected by the server. Free the handle either way.
///
/// # Safety
/// `auth` must be a live handle from [`vault_ffi_sync_auth_begin`]; `code` a
/// NUL-terminated C string; the out-pointers writable.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_sync_auth_finish(
    auth: *mut SyncAuth,
    code: *const c_char,
    out_refresh_token: *mut *mut u8,
    out_refresh_token_len: *mut usize,
    out_account: *mut *mut u8,
    out_account_len: *mut usize,
) -> i32 {
    if auth.is_null()
        || code.is_null()
        || out_refresh_token.is_null()
        || out_refresh_token_len.is_null()
        || out_account.is_null()
        || out_account_len.is_null()
    {
        return ERR_NULL_ARG;
    }
    *out_refresh_token = std::ptr::null_mut();
    *out_refresh_token_len = 0;
    *out_account = std::ptr::null_mut();
    *out_account_len = 0;

    let Some(code) = cstr(code) else {
        return ERR_UTF8;
    };
    let auth = &*auth;

    let exchanged = catch_unwind(AssertUnwindSafe(|| {
        auth.oauth
            .exchange_code(code, &auth.pkce, &auth.redirect_uri)
    }));
    let tokens = match exchanged {
        Ok(Ok(tokens)) => tokens,
        Ok(Err(_)) => return ERR_SYNC_FAILED,
        Err(_) => return ERR_PANIC,
    };

    let account = catch_unwind(AssertUnwindSafe(|| {
        vault_sync::drive::account_email(&tokens.access_token)
    }))
    .ok()
    .flatten();

    emit(
        tokens.refresh_token.as_bytes().to_vec(),
        out_refresh_token,
        out_refresh_token_len,
    );
    if let Some(account) = account {
        emit(account.into_bytes(), out_account, out_account_len);
    }
    OK
}

/// Free a sign-in handle, zeroizing the PKCE verifier. Passing null is a no-op.
///
/// # Safety
/// `auth` must come from [`vault_ffi_sync_auth_begin`] (or be null), freed once.
#[no_mangle]
pub unsafe extern "C" fn vault_ffi_sync_auth_free(auth: *mut SyncAuth) {
    if auth.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| drop(Box::from_raw(auth))));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    // Nothing here touches the network. What is testable without a Google
    // account is exactly the part where a mistake costs data: what the engine
    // does to the shared vault, and what it hands back to be written.

    /// Deliberately weak Argon2id parameters: these tests are about merge
    /// behaviour, not key derivation, and the real cost would dominate them.
    fn cheap_params() -> vault_core::KdfParams {
        vault_core::KdfParams {
            algorithm: vault_core::KdfAlgorithm::Argon2id,
            m_cost_kib: 256,
            t_cost: 1,
            p_cost: 1,
            salt: vec![7u8; vault_core::KdfParams::SALT_LEN],
        }
    }

    fn login(title: &str, id: u8, modified_at: i64) -> vault_core::Item {
        let mut item = vault_core::Item::new(
            vault_core::VaultItem::Login {
                title: title.into(),
                username: "u".into(),
                password: "p".into(),
                url: "https://example.test".into(),
                totp_secret: None,
                notes: String::new(),
            },
            modified_at,
        );
        item.id = uuid::Uuid::from_bytes([id; 16]);
        item
    }

    fn vault_with(title: &str, id: u8) -> Vault {
        let mut vault = Vault::create("pw", cheap_params()).unwrap();
        vault.upsert_item(login(title, id, 1_000)).unwrap();
        vault
    }

    fn shared(vault: Vault) -> (Arc<Mutex<Vault>>, Arc<SharedVault>) {
        let arc = Arc::new(Mutex::new(vault));
        let local = Arc::new(SharedVault {
            vault: arc.clone(),
            pending: Mutex::new(None),
        });
        (arc, local)
    }

    fn titles(vault: &Arc<Mutex<Vault>>) -> Vec<String> {
        let mut t: Vec<String> = vault
            .lock()
            .unwrap()
            .list_items(false)
            .unwrap()
            .into_iter()
            .map(|s| s.title)
            .collect();
        t.sort();
        t
    }

    /// The whole reason the vault is shared rather than copied: a merge has to
    /// land in the vault the caller is already reading through its handle, or
    /// the UI shows stale data until someone reopens the file.
    #[test]
    fn a_merge_lands_in_the_vault_the_caller_still_holds() {
        let (arc, local) = shared(vault_with("mine", 1));

        // A peer's copy of the same vault, carrying an extra item.
        let peer_bytes = {
            let mut peer = Vault::from_bytes(&arc.lock().unwrap().to_bytes().unwrap()).unwrap();
            peer.unlock("pw").unwrap();
            peer.upsert_item(login("theirs", 2, 2_000)).unwrap();
            peer.to_bytes().unwrap()
        };

        local.merge_and_serialize(&[peer_bytes]).unwrap();
        assert_eq!(titles(&arc), vec!["mine", "theirs"]);
    }

    /// Serializing re-encrypts with fresh nonces, so "the bytes changed" is not
    /// evidence the vault did. Handing them back regardless would rewrite the
    /// user's file on every idle cycle.
    #[test]
    fn nothing_is_handed_back_to_persist_when_nothing_was_merged() {
        let (_arc, local) = shared(vault_with("mine", 1));

        let bytes = local.merge_and_serialize(&[]).unwrap();
        assert!(!bytes.is_empty(), "the push still needs bytes to upload");
        assert!(
            local.pending.lock().unwrap().is_none(),
            "an empty merge must not ask the caller to rewrite the vault file"
        );
    }

    #[test]
    fn a_merge_leaves_bytes_for_the_caller_to_persist() {
        let (arc, local) = shared(vault_with("mine", 1));
        let peer_bytes = arc.lock().unwrap().to_bytes().unwrap();

        local.merge_and_serialize(&[peer_bytes]).unwrap();
        let pending = local.pending.lock().unwrap().clone();
        let pending = pending.expect("a merge must produce bytes to write");

        // What is handed over has to be a vault, and the user's own password
        // has to still open it — this is about to overwrite their only copy.
        let mut reopened = Vault::from_bytes(&pending).unwrap();
        reopened.unlock("pw").unwrap();
        assert_eq!(reopened.list_items(false).unwrap().len(), 1);
    }

    /// A locked vault cannot be merged into. It must read as "defer", not as a
    /// failure, or the engine would drop the changes it was holding.
    #[test]
    fn a_locked_vault_defers_rather_than_failing() {
        let mut vault = vault_with("mine", 1);
        vault.lock().unwrap();
        let (_arc, local) = shared(vault);

        assert!(matches!(
            local.merge_and_serialize(&[]),
            Err(LocalError::Locked)
        ));
    }

    /// A remote written by a newer Arca is refused, never "repaired" — the
    /// classification comes from vault-sync, and this checks it survives the
    /// trip through the FFI's LocalVault rather than being flattened.
    #[test]
    fn a_foreign_remote_is_refused_and_the_local_vault_is_untouched() {
        let (arc, local) = shared(vault_with("mine", 1));

        // A different vault entirely: same shape, different key. It needs an
        // item in it — the refusal comes from failing to decrypt the remote's
        // items with our vault key, so an *empty* foreign vault has nothing to
        // fail on and merges as a no-op.
        let foreign = {
            let mut other = Vault::create("other-password", cheap_params()).unwrap();
            other.upsert_item(login("theirs", 9, 2_000)).unwrap();
            other.to_bytes().unwrap()
        };

        assert!(matches!(
            local.merge_and_serialize(&[foreign]),
            Err(LocalError::Refused(_))
        ));
        assert_eq!(titles(&arc), vec!["mine"], "a refusal must change nothing");
        assert!(local.pending.lock().unwrap().is_none());
    }

    #[test]
    fn a_disconnected_engine_reports_itself_and_does_no_work() {
        let vault = vault_with("mine", 1);
        let mut handle: *mut VaultHandle = std::ptr::null_mut();
        let bytes = vault.to_bytes().unwrap();
        let pw = CString::new("pw").unwrap();
        assert_eq!(
            unsafe {
                crate::vault_ffi_vault_open_password(
                    bytes.as_ptr(),
                    bytes.len(),
                    pw.as_ptr(),
                    &mut handle,
                )
            },
            OK
        );

        let mut sync: *mut SyncHandle = std::ptr::null_mut();
        assert_eq!(unsafe { vault_ffi_sync_new(handle, &mut sync) }, OK);
        assert!(!sync.is_null());

        // No credential: the cycle must return without touching the network.
        // If this test ever hangs or fails on a machine with no route to
        // Google, that guard has stopped working.
        let (mut vb, mut vl) = (std::ptr::null_mut(), 0usize);
        let (mut sj, mut sl) = (std::ptr::null_mut(), 0usize);
        assert_eq!(
            unsafe { vault_ffi_sync_now(sync, &mut vb, &mut vl, &mut sj, &mut sl) },
            OK
        );
        assert!(vb.is_null(), "nothing to persist when nothing synced");

        let status = unsafe { std::slice::from_raw_parts(sj, sl) };
        let status: serde_json::Value = serde_json::from_slice(status).unwrap();
        assert_eq!(status["connected"], false);
        assert_eq!(status["merged"], false);
        assert!(status["account"].is_null());
        unsafe { crate::vault_ffi_free(sj, sl) };

        unsafe { vault_ffi_sync_free(sync) };
        unsafe { crate::vault_ffi_vault_free(handle) };
    }

    #[test]
    fn a_credential_connects_and_clearing_it_disconnects() {
        let vault = vault_with("mine", 1);
        let bytes = vault.to_bytes().unwrap();
        let mut handle: *mut VaultHandle = std::ptr::null_mut();
        let pw = CString::new("pw").unwrap();
        unsafe {
            crate::vault_ffi_vault_open_password(
                bytes.as_ptr(),
                bytes.len(),
                pw.as_ptr(),
                &mut handle,
            )
        };
        let mut sync: *mut SyncHandle = std::ptr::null_mut();
        unsafe { vault_ffi_sync_new(handle, &mut sync) };

        let token = CString::new("refresh-token").unwrap();
        let account = CString::new("someone@example.test").unwrap();
        assert_eq!(
            unsafe { vault_ffi_sync_set_credential(sync, token.as_ptr(), account.as_ptr()) },
            OK
        );

        let read_status = |sync: *mut SyncHandle| -> serde_json::Value {
            let (mut p, mut n) = (std::ptr::null_mut(), 0usize);
            assert_eq!(unsafe { vault_ffi_sync_status(sync, &mut p, &mut n) }, OK);
            let v = serde_json::from_slice(unsafe { std::slice::from_raw_parts(p, n) }).unwrap();
            unsafe { crate::vault_ffi_free(p, n) };
            v
        };

        let status = read_status(sync);
        assert_eq!(status["connected"], true);
        assert_eq!(status["account"], "someone@example.test");

        // Null token disconnects, and the label goes with it — leaving an
        // account name on screen after a sign-out reads as still signed in.
        assert_eq!(
            unsafe { vault_ffi_sync_set_credential(sync, std::ptr::null(), std::ptr::null()) },
            OK
        );
        let status = read_status(sync);
        assert_eq!(status["connected"], false);
        assert!(status["account"].is_null());

        unsafe { vault_ffi_sync_free(sync) };
        unsafe { crate::vault_ffi_vault_free(handle) };
    }

    /// The sign-in URL is built without a network round trip, so this checks
    /// the whole of what the browser will be handed.
    #[test]
    fn the_authorization_url_is_complete_and_carries_no_secret() {
        let redirect = CString::new("no.sybr.vault.ios:/oauth").unwrap();
        let (mut url, mut len) = (std::ptr::null_mut(), 0usize);
        let mut auth: *mut SyncAuth = std::ptr::null_mut();
        assert_eq!(
            unsafe { vault_ffi_sync_auth_begin(redirect.as_ptr(), &mut url, &mut len, &mut auth) },
            OK
        );
        assert!(!auth.is_null());

        let url = String::from_utf8(unsafe { std::slice::from_raw_parts(url, len) }.to_vec())
            .expect("the URL is UTF-8");
        assert!(url.starts_with("https://accounts.google.com/"));
        assert!(url.contains("code_challenge_method=S256"));
        // Without these Google returns no refresh token, and sync works
        // exactly until the first access token expires.
        assert!(url.contains("access_type=offline"));
        assert!(url.contains("prompt=consent"));
        assert!(url.contains("redirect_uri=no.sybr.vault.ios%3A%2Foauth"));
        assert!(
            !url.contains("code_verifier"),
            "the verifier must never reach the browser — it is what makes PKCE work"
        );
        assert!(!url.contains("GOCSPX"), "no client secret in a browser URL");

        unsafe { vault_ffi_sync_auth_free(auth) };
    }

    /// Every entry point has to survive the arguments a caller gets wrong,
    /// because a crash inside a credential provider takes the keyboard with it.
    #[test]
    fn null_arguments_are_errors_and_freeing_null_is_safe() {
        let mut out: *mut SyncHandle = std::ptr::null_mut();
        assert_eq!(
            unsafe { vault_ffi_sync_new(std::ptr::null_mut(), &mut out) },
            ERR_NULL_ARG
        );
        assert_eq!(
            unsafe {
                vault_ffi_sync_set_credential(
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            },
            ERR_NULL_ARG
        );
        let (mut a, mut b) = (std::ptr::null_mut(), 0usize);
        assert_eq!(
            unsafe { vault_ffi_sync_status(std::ptr::null_mut(), &mut a, &mut b) },
            ERR_NULL_ARG
        );
        assert_eq!(
            unsafe { vault_ffi_sync_now(std::ptr::null_mut(), &mut a, &mut b, &mut a, &mut b) },
            ERR_NULL_ARG
        );
        let mut auth: *mut SyncAuth = std::ptr::null_mut();
        assert_eq!(
            unsafe { vault_ffi_sync_auth_begin(std::ptr::null(), &mut a, &mut b, &mut auth) },
            ERR_NULL_ARG
        );
        assert_eq!(
            unsafe {
                vault_ffi_sync_auth_finish(
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    &mut a,
                    &mut b,
                    &mut a,
                    &mut b,
                )
            },
            ERR_NULL_ARG
        );

        unsafe { vault_ffi_sync_free(std::ptr::null_mut()) };
        unsafe { vault_ffi_sync_auth_free(std::ptr::null_mut()) };
        unsafe { vault_ffi_sync_mark_dirty(std::ptr::null_mut()) };
    }
}
