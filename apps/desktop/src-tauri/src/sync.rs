//! Google Drive sync, wired to Tauri.
//!
//! The transport and the pull→merge→push cycle live in [`vault_sync`]; what is
//! left here is everything that is genuinely about *this* app: the desktop's
//! loopback OAuth flow, the OS secret store, the app state the vault lives in,
//! and the events the webview listens for.
//!
//! Security model, unchanged and worth restating: Drive stores CIPHERTEXT ONLY.
//! The vault is sealed with Argon2id + XChaCha20-Poly1305 before it leaves the
//! machine, the scope is `drive.appdata` (Arca's own hidden folder, nothing
//! else in the account), and the refresh token sits in the OS secret store
//! *without* a biometric gate — the background loop has to read it silently and
//! it only ever unlocks ciphertext.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager};
use vault_sync::drive::{arca_credentials, sync_configured, DriveStore, RefreshTokenStore};
use vault_sync::oauth::{OAuthClient, Pkce};
use vault_sync::{
    LocalError, LocalVault, Push, RemoteStore, SyncEngine, SyncObserver, SyncStatus, ThisDevice,
};
use zeroize::Zeroizing;

use crate::state::AppState;

/// Keychain slot for the refresh token.
const SECRET_SERVICE: &str = "no.sybr.vault";
const SECRET_ACCOUNT: &str = "gdrive-refresh-token";

/// Background sync cadence.
const SYNC_INTERVAL: Duration = Duration::from_secs(30);

/// How long the browser gets to complete the sign-in before we stop listening.
const SIGN_IN_TIMEOUT: Duration = Duration::from_secs(180);

// ---------------------------------------------------------------------------
// The platform's side of the three traits
// ---------------------------------------------------------------------------

/// The refresh token in the OS secret store (macOS Keychain, Windows
/// Credential Manager, Linux Secret Service).
struct KeychainTokens;

impl RefreshTokenStore for KeychainTokens {
    fn exists(&self) -> bool {
        // Presence only. Reading the DATA runs the item's ACL and can raise a
        // prompt (e.g. after a code-signature change); the engine asks this
        // every tick, so it must never be able to interrupt the user.
        vault_store::secrets::exists(SECRET_SERVICE, SECRET_ACCOUNT)
    }

    fn read(&self) -> Result<Option<Zeroizing<String>>, String> {
        vault_store::secrets::get(SECRET_SERVICE, SECRET_ACCOUNT)
            .map_err(|_| "keychain read failed".to_string())
    }
}

/// The vault inside the app's shared state.
struct AppStateVault {
    app: AppHandle,
    device: ThisDevice,
}

impl LocalVault for AppStateVault {
    fn merge_and_serialize(&self, remotes: &[Vec<u8>], whole: bool) -> Result<Push, LocalError> {
        // Held across the merge and the save so no command can write the vault
        // underneath us. No network happens inside this lock.
        let state = self.app.state::<Mutex<AppState>>();
        let mut guard = state
            .lock()
            .map_err(|_| LocalError::Save("app state poisoned".into()))?;
        let pushed = merge_into(&mut guard, remotes, whole, &self.device);
        if let Err(LocalError::KeyRotated(copy)) = &pushed {
            // Kept beside the vault: from now on only the new password opens
            // it here, and nothing that wrapped the old key does.
            if crate::pending_change::record(&guard, copy) {
                crate::pending_change::drop_quick_unlock(&guard.store);
            }
        }
        pushed
    }
}

fn merge_into(
    st: &mut AppState,
    remotes: &[Vec<u8>],
    whole: bool,
    device: &ThisDevice,
) -> Result<Push, LocalError> {
    let AppState { store, vault, .. } = st;
    let Some(vault) = vault.as_mut() else {
        return Err(LocalError::Locked);
    };
    if !vault.is_unlocked() {
        // Merging needs the key, so the engine defers — unless the password
        // changed elsewhere, which the lock screen needs to know.
        return Err(vault_sync::locked(vault, remotes));
    }
    let behind = merge_and_save(vault, store, remotes, whole, device)?;
    let bytes = vault
        .to_bytes()
        .map_err(|e| LocalError::Save(e.to_string()))?;
    Ok(Push { bytes, behind })
}

fn merge_and_save(
    vault: &mut vault_core::Vault,
    store: &vault_store::VaultStore,
    remotes: &[Vec<u8>],
    whole: bool,
    device: &ThisDevice,
) -> Result<Vec<vault_core::Device>, LocalError> {
    let before = vault.clone();
    let result = vault_sync::prepare_push(vault, remotes, whole, Some(device)).and_then(|behind| {
        store
            .save_synced(vault)
            .map_err(|e| LocalError::Save(e.to_string()))?;
        Ok(behind)
    });
    if result.is_err() {
        *vault = before;
    }
    result
}

/// This installation as it records itself in the copies it pushes: a random
/// id kept in `device-id` next to the vault, which never syncs, and the name
/// the user gave the computer.
fn this_device(app: &AppHandle) -> ThisDevice {
    let path = app
        .state::<Mutex<AppState>>()
        .lock()
        .ok()
        .map(|st| st.store.path().with_file_name("device-id"));
    let stored = path
        .as_ref()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|id| uuid::Uuid::parse_str(id.trim()).ok());
    let id = stored.unwrap_or_else(|| {
        let id = uuid::Uuid::new_v4();
        // Unsaved, this id lasts until Arca quits: the next launch counts as
        // another device, which is untidy but loses nothing.
        if let Some(path) = &path {
            let _ = vault_store::write_atomic(path, id.to_string().as_bytes());
        }
        id
    });
    ThisDevice {
        id,
        name: computer_name(),
    }
}

/// The computer's name as the user set it, or a plain description.
fn computer_name() -> String {
    #[cfg(target_os = "macos")]
    let name = std::process::Command::new("scutil")
        .args(["--get", "ComputerName"])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .and_then(|out| String::from_utf8(out.stdout).ok());
    #[cfg(target_os = "windows")]
    let name = std::env::var("COMPUTERNAME").ok();
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let name = std::fs::read_to_string("/etc/hostname").ok();
    name.map(|name| name.trim().to_string())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "This computer".to_string())
}

/// Sync progress as webview events.
struct TauriEvents {
    app: AppHandle,
}

impl SyncObserver for TauriEvents {
    fn merged(&self) {
        let _ = self.app.emit("sync-merged", ());
    }

    fn status_changed(&self, status: &SyncStatus) {
        let _ = self.app.emit("sync-status", dto(status));
    }
}

// ---------------------------------------------------------------------------
// The one engine
// ---------------------------------------------------------------------------

struct Sync {
    engine: Arc<SyncEngine>,
    /// The same store the engine holds, kept concretely so sign-in can seed the
    /// access token and read the account label.
    drive: Arc<DriveStore>,
    /// This computer, as the copies it pushes name it.
    device: ThisDevice,
    /// The vault file, for what is kept beside it. Read without the app state,
    /// whose lock the persist paths already hold when they mark sync dirty.
    vault_path: Option<std::path::PathBuf>,
}

/// One vault, one sync loop, one process. A global because [`mark_dirty`] is
/// called from persist paths that have no `AppHandle` to reach state through —
/// `commands::persist` takes only `&mut AppState`, and the browser bridge's
/// handle is optional.
static SYNC: OnceLock<Sync> = OnceLock::new();

fn sync(app: &AppHandle) -> &'static Sync {
    SYNC.get_or_init(|| {
        let drive = Arc::new(DriveStore::new(
            arca_credentials(),
            Arc::new(KeychainTokens),
        ));
        let device = this_device(app);
        let vault_path = app
            .state::<Mutex<AppState>>()
            .lock()
            .ok()
            .map(|st| st.store.path().to_path_buf());
        let engine = Arc::new(SyncEngine::new(
            drive.clone(),
            Arc::new(AppStateVault {
                app: app.clone(),
                device: device.clone(),
            }),
            Arc::new(TauriEvents { app: app.clone() }),
        ));
        Sync {
            engine,
            drive,
            device,
            vault_path,
        }
    })
}

/// Mark that local vault state changed and should be pushed on the next cycle.
///
/// A no-op before the first cycle has set the engine up, which is correct: a
/// fresh engine starts dirty, so nothing is lost.
pub fn mark_dirty() {
    if let Some(sync) = SYNC.get() {
        sync.engine.mark_dirty();
    }
}

/// The copy sealed by a master password change made on another device, while
/// sync waits for its password (see `rotation::adopt`).
pub fn rotated_copy() -> Option<Vec<u8>> {
    SYNC.get()?.engine.rotated_copy()
}

/// The vault took that change on: stop asking, and push it.
pub fn rotation_adopted() {
    if let Some(sync) = SYNC.get() {
        sync.engine.rotation_adopted();
    }
}

/// Sync status as the webview sees it.
#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SyncStatusDto {
    pub pending: bool,
    pub syncing: bool,
    pub connected: bool,
    pub account: Option<String>,
    pub last_sync_unix: Option<u64>,
    pub last_error: Option<String>,
    /// The master password was changed on another device; see [`rotated_copy`].
    pub needs_password: bool,
    /// Devices whose latest changes Drive had lost, until the user has seen it.
    pub rolled_back: Vec<String>,
}

impl From<&SyncStatus> for SyncStatusDto {
    fn from(s: &SyncStatus) -> Self {
        Self {
            pending: s.pending,
            syncing: s.syncing,
            connected: s.connected,
            account: s.account.clone(),
            last_sync_unix: s.last_sync_unix,
            last_error: s.last_error.clone(),
            needs_password: s.needs_password,
            rolled_back: s.rolled_back.clone(),
        }
    }
}

/// A device that pushes this vault, as Settings lists it.
#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DeviceDto {
    pub name: String,
    /// When it last pushed, by its own clock (Unix ms).
    pub last_upload: i64,
    pub this_device: bool,
}

/// Every device that pushes this vault, this one first. Empty while locked.
pub fn devices(app: &AppHandle) -> Vec<DeviceDto> {
    let me = sync(app).device.id;
    let state = app.state::<Mutex<AppState>>();
    let Ok(st) = state.lock() else {
        return Vec::new();
    };
    let Some(Ok(devices)) = st.vault.as_ref().map(vault_core::Vault::devices) else {
        return Vec::new();
    };
    let mut list: Vec<DeviceDto> = devices
        .iter()
        .map(|d| DeviceDto {
            name: d.name.clone(),
            last_upload: d.last_upload,
            this_device: d.id == me,
        })
        .collect();
    list.sort_by_key(|d| (!d.this_device, -d.last_upload));
    list
}

/// The user has seen that Drive went back in time.
pub fn acknowledge_rollback(app: &AppHandle) {
    sync(app).engine.acknowledge_rollback();
}

/// Status DTO for the UI.
pub fn status(app: &AppHandle) -> SyncStatusDto {
    dto(&sync(app).engine.status())
}

/// A change the user said was not theirs asks for no password: every cycle
/// still finds the copy that claims it, and asking again would contradict them.
fn dto(status: &SyncStatus) -> SyncStatusDto {
    let mut dto = SyncStatusDto::from(status);
    if dto.needs_password {
        if let Some(sync) = SYNC.get() {
            let denied = sync.vault_path.as_deref().is_some_and(|path| {
                sync.engine
                    .rotated_copy()
                    .is_some_and(|copy| crate::pending_change::is_denied_at(path, &copy))
            });
            dto.needs_password = !denied;
        }
    }
    dto
}

/// Run sync now (the background loop and the manual "Sync now" both land here).
pub fn sync_now(app: &AppHandle) -> Result<bool, String> {
    sync(app).engine.sync_now()
}

/// Background loop: a cycle at launch and every [`SYNC_INTERVAL`] after.
/// Errors land in the status (shown in Settings), never fatal. The first one
/// runs at once, locked or not: a password changed on another device should
/// be on the lock screen before the user types the old one.
pub fn start_loop(app: AppHandle) {
    std::thread::spawn(move || loop {
        let _ = sync_now(&app);
        std::thread::sleep(SYNC_INTERVAL);
    });
}

// ---------------------------------------------------------------------------
// Sign-in: PKCE + a loopback redirect
// ---------------------------------------------------------------------------

/// Run the interactive sign-in: open the browser, catch the redirect on a
/// loopback port, exchange the code, store the refresh token. Blocking (call it
/// from a thread); returns the account label.
///
/// This is the part that stayed behind. iOS has no equivalent — it cannot bind
/// a listening socket and uses `ASWebAuthenticationSession` with a custom URL
/// scheme instead — so the shared crate builds the URL and redeems the code,
/// and each platform runs the middle step its own way.
pub fn connect(app: &AppHandle) -> Result<String, String> {
    // Before the browser opens, not after. An unconfigured build can still walk
    // the user all the way through Google's consent screen and only fail at the
    // token exchange, with a message from Google about a client they have never
    // heard of.
    if !sync_configured() {
        return Err(vault_sync::drive::UNCONFIGURED.to_string());
    }
    let pkce = Pkce::generate()?;
    let listener = TcpListener::bind(("127.0.0.1", 0)).map_err(|e| format!("bind failed: {e}"))?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    let redirect = format!("http://127.0.0.1:{port}");

    let oauth = OAuthClient::new(arca_credentials());
    {
        use tauri_plugin_opener::OpenerExt;
        app.opener()
            .open_url(oauth.authorization_url(&redirect, &pkce), None::<&str>)
            .map_err(|e| format!("could not open the browser: {e}"))?;
    }

    let code = await_redirect(listener)?;
    let tokens = oauth.exchange_code(&code, &pkce, &redirect)?;

    vault_store::secrets::set(SECRET_SERVICE, SECRET_ACCOUNT, &tokens.refresh_token)
        .map_err(|_| "could not store the refresh token in the OS keychain")?;

    let sync = sync(app);
    // Seed the token we already hold rather than spending a refresh to get the
    // account label, and drop any previous account's bookkeeping: a checksum
    // from someone else's Drive means nothing here.
    sync.drive
        .cache_access_token(tokens.access_token, tokens.expires_in);
    let account = sync
        .drive
        .account_email()
        .unwrap_or_else(|| "Google account".to_string());
    sync.engine.set_account(Some(account.clone()));
    Ok(account)
}

/// First-run restore: adopt the vault that already lives in the signed-in
/// Google account as THIS device's vault.
///
/// This is the path [`merge_remotes`]' refusal deliberately leaves open. A
/// fresh install that *creates* a vault mints a new vault key; the copy on
/// Drive is sealed with the real one, so every sync after that is refused with
/// a "corrupt/tampered" decryption error — technically true, humanly wrong,
/// and the user's actual vault is unreachable. The right first-run question is
/// "do you already have a vault?", and this is the yes branch: download the
/// remote, unlock it with the master password (proving it is theirs), and make
/// it the local vault. No merge is involved, so the shared-vault-key invariant
/// holds from the first cycle.
///
/// Blocking (network + Argon2id); call from a thread. Refuses to run when a
/// local vault file already exists — replacing an existing vault stays a
/// deliberate, separate act, not something a lock-screen button can do.
pub fn bootstrap(app: &AppHandle, master_password: &str) -> Result<(), String> {
    if !sync_configured() {
        return Err(vault_sync::drive::UNCONFIGURED.to_string());
    }
    let sync = sync(app);
    if !sync.drive.is_connected() {
        return Err("Sign in with Google first.".into());
    }

    // Network and key derivation happen BEFORE the state lock: nothing below
    // may stall the UI's other commands behind a download or an Argon2id run.
    let files = sync.drive.list().map_err(|e| e.to_string())?;
    if files.is_empty() {
        return Err("No vault was found in this Google account.".into());
    }
    // The copy from the latest master password change, whose password is the
    // one the user knows. Otherwise the oldest (the `list` order): after a
    // historical create race, that is the lineage every device converged on.
    let mut newest: Option<vault_core::Vault> = None;
    for file in &files {
        let bytes = sync.drive.download(&file.id).map_err(|e| e.to_string())?;
        let Ok(copy) = vault_core::Vault::from_bytes(&bytes) else {
            continue;
        };
        let newer = match &newest {
            Some(kept) => copy.header().key_epoch > kept.header().key_epoch,
            None => true,
        };
        if newer {
            newest = Some(copy);
        }
    }
    let mut vault =
        newest.ok_or_else(|| "The synced file could not be read as a vault.".to_string())?;
    vault.unlock(master_password).map_err(|e| match e {
        // In this flow a decryption failure has exactly one human meaning.
        vault_core::Error::Decryption => "Wrong master password for the synced vault.".to_string(),
        e => e.to_string(),
    })?;

    let state = app.state::<Mutex<AppState>>();
    let mut st = state.lock().map_err(|_| "app state poisoned".to_string())?;
    if st.store.exists() {
        return Err("A vault already exists on this device.".into());
    }
    st.store.save(&vault).map_err(|e| e.to_string())?;
    st.unlock_generation = st.unlock_generation.wrapping_add(1);
    st.vault = Some(vault);
    st.touch();
    Ok(())
}

/// Forget the connection: delete the refresh token and clear state.
pub fn disconnect(app: &AppHandle) {
    let _ = vault_store::secrets::delete(SECRET_SERVICE, SECRET_ACCOUNT);
    let sync = sync(app);
    sync.drive.invalidate_auth();
    sync.engine.forget_account();
}

/// Wait for the browser to hit `http://127.0.0.1:<port>/?code=…`, answer it
/// with a page the user can close, and return the code.
fn await_redirect(listener: TcpListener) -> Result<String, String> {
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    let deadline = Instant::now() + SIGN_IN_TIMEOUT;
    loop {
        if Instant::now() > deadline {
            return Err("sign-in timed out".into());
        }
        let stream = match listener.accept() {
            Ok((s, _)) => s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(150));
                continue;
            }
            Err(_) => continue,
        };
        // The accepted stream inherits nonblocking; make it a blocking read with
        // a short timeout so a stalled local connection cannot hang us.
        stream.set_nonblocking(false).ok();
        stream.set_read_timeout(Some(Duration::from_secs(2))).ok();
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).ok();

        // "GET /?code=...&scope=... HTTP/1.1" or "GET /?error=access_denied ..."
        let path = line.split_whitespace().nth(1).unwrap_or("");
        let denied = path.contains("error=");
        let code = path
            .split_once("code=")
            .map(|(_, rest)| rest.split('&').next().unwrap_or("").to_string())
            .filter(|c| !c.is_empty());

        let mut stream = reader.into_inner();
        let body = if code.is_some() {
            "<h2>Arca is connected.</h2>You can close this tab."
        } else {
            "<h2>Sign-in was cancelled.</h2>You can close this tab."
        };
        let _ = stream.write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .as_bytes(),
        );

        if denied {
            return Err("sign-in was denied".into());
        }
        if let Some(code) = code {
            return Ok(code);
        }
        // A favicon request or other noise: keep waiting for the real redirect.
    }
}

#[cfg(test)]
mod persistence_tests {
    use super::*;
    #[test]
    fn a_failed_sync_save_does_not_expose_an_uncommitted_merge() {
        let dir = tempfile::tempdir().unwrap();
        let blocked = dir.path().join("blocked");
        std::fs::write(&blocked, b"not a folder").unwrap();
        let store = vault_store::VaultStore::new(blocked.join("vault"), "test", "test");
        let mut params = vault_core::KdfParams::new_default().unwrap();
        params.m_cost_kib = 256;
        params.t_cost = 1;
        let mut local = vault_core::Vault::create("pw", params).unwrap();
        let mut remote = local.clone();
        let item = vault_core::Item::new(
            vault_core::VaultItem::SecureNote {
                title: "remote".into(),
                body: "uncommitted".into(),
            },
            1,
        );
        let id = item.id;
        remote.upsert_item(item).unwrap();
        let device = ThisDevice {
            id: uuid::Uuid::new_v4(),
            name: "test".into(),
        };
        let remotes = [remote.to_bytes().unwrap()];
        assert!(merge_and_save(&mut local, &store, &remotes, true, &device).is_err());
        assert!(local.get_item(id).is_err());
        assert!(
            local.devices().unwrap().is_empty(),
            "the upload was not recorded"
        );
    }
}
