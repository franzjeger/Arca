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
use vault_sync::{LocalError, LocalVault, RemoteStore, SyncEngine, SyncObserver, SyncStatus};
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
}

impl LocalVault for AppStateVault {
    fn merge_and_serialize(&self, remotes: &[Vec<u8>]) -> Result<Vec<u8>, LocalError> {
        // Held across the merge and the save so no command can write the vault
        // underneath us. No network happens inside this lock.
        let state = self.app.state::<Mutex<AppState>>();
        let mut guard = state
            .lock()
            .map_err(|_| LocalError::Save("app state poisoned".into()))?;
        let AppState { store, vault, .. } = &mut *guard;
        let Some(vault) = vault.as_mut().filter(|v| v.is_unlocked()) else {
            // Locked: merging needs the key. Not an error — the engine defers.
            return Err(LocalError::Locked);
        };
        merge_and_save(vault, store, remotes)?;
        vault
            .to_bytes()
            .map_err(|e| LocalError::Save(e.to_string()))
    }
}

fn merge_and_save(
    vault: &mut vault_core::Vault,
    store: &vault_store::VaultStore,
    remotes: &[Vec<u8>],
) -> Result<(), LocalError> {
    let before = vault.clone();
    let result = vault_sync::merge_remotes(vault, remotes).and_then(|()| {
        store
            .save_synced(vault)
            .map_err(|e| LocalError::Save(e.to_string()))
    });
    if result.is_err() {
        *vault = before;
    }
    result.map(|_| ())
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
        let _ = self.app.emit("sync-status", SyncStatusDto::from(status));
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
        let engine = Arc::new(SyncEngine::new(
            drive.clone(),
            Arc::new(AppStateVault { app: app.clone() }),
            Arc::new(TauriEvents { app: app.clone() }),
        ));
        Sync { engine, drive }
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
        }
    }
}

/// Status DTO for the UI.
pub fn status(app: &AppHandle) -> SyncStatusDto {
    SyncStatusDto::from(&sync(app).engine.status())
}

/// Run sync now (the background loop and the manual "Sync now" both land here).
pub fn sync_now(app: &AppHandle) -> Result<bool, String> {
    sync(app).engine.sync_now()
}

/// Background loop: a cycle every [`SYNC_INTERVAL`]. Errors land in the status
/// (shown in Settings), never fatal.
pub fn start_loop(app: AppHandle) {
    std::thread::spawn(move || loop {
        std::thread::sleep(SYNC_INTERVAL);
        let _ = sync_now(&app);
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
    // Oldest first (the `list` contract): after a historical create race the
    // oldest file is the lineage every other device converged on.
    let Some(primary) = files.first() else {
        return Err("No vault was found in this Google account.".into());
    };
    let bytes = sync
        .drive
        .download(&primary.id)
        .map_err(|e| e.to_string())?;
    let mut vault = vault_core::Vault::from_bytes(&bytes)
        .map_err(|_| "The synced file could not be read as a vault.".to_string())?;
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
        assert!(merge_and_save(&mut local, &store, &[remote.to_bytes().unwrap()]).is_err());
        assert!(local.get_item(id).is_err());
    }
}
