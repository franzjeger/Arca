//! Unlock with a key file on a USB stick — a possession factor that works on
//! every desktop, alongside Touch ID, Windows Hello and the keychain.
//!
//! Linux has no biometric the app can call, so every unlock there was the
//! master password: after each idle lock, before each browser fill, for each
//! passkey. On the other desktops the stick is a second way in — a machine
//! without Hello, a Mac whose Touch ID is under a closed lid.
//!
//! HOW IT WORKS. Enrollment writes a file of random bytes to the stick (or
//! adopts the one already there) and keeps a second random value — the
//! *pepper* — in a `0600` file next to the vault, together with the vault key
//! wrapped under `HMAC-SHA256(pepper, secret)`. Unlocking reads the file back,
//! re-derives that key and unwraps: no prompt, no password.
//!
//! WHY THE WRAP LIVES IN THE SIDECAR, NOT THE HEADER. The header already has
//! one device slot, it is bincode-serialised (a new field is a format bump for
//! every client), and it travels with the vault. The sidecar is local and
//! never syncs, so the key file coexists with the biometric slot instead of
//! competing for it, and each machine binds the same stick with its own pepper
//! and its own wrap. One file on the stick, any number of computers.
//!
//! WHY TWO HALVES. Neither piece is useful alone. The vault file travels —
//! sync, Drive, backups — but the pepper and the wrap do not; a lost stick
//! plus any copy of the vault opens nothing. A disk image without the stick
//! has a pepper, a wrap and no secret. They are only ever together on this
//! machine with the stick inserted, which is exactly when the vault should
//! open.
//!
//! WHAT IT IS NOT. A possession factor with no user-presence test. Whoever
//! holds the laptop and the stick together holds the vault; same-user code
//! running while the stick is inserted can read both halves (THREAT_MODEL.md
//! T9/T15). The desktop still asks before creating passkeys and re-confirms
//! the master password for exports and the like — this only replaces the
//! unlock.
//!
//! The key file is the identity: it carries a random id the sidecar also
//! records, and it is looked for on every removable root the platform has
//! (`/run/media/*/*` and `/media/*`, `/Volumes/*`, `D:`–`Z:`). Linux also
//! knows the filesystem UUID so it can mount the stick through udisks2 when
//! the desktop has not. Removal locks the vault (opt-out), insertion unlocks
//! it, and a browser request that finds the vault locked while the stick is
//! in unlocks it silently.

use crate::state::{AppState, CmdError};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager};
use vault_core::crypto::AeadBlob;
use vault_core::{SymmetricKey, KEY_LEN};
use vault_store::VaultStore;
use zeroize::Zeroizing;

const CONFIG_FILE: &str = "keyfile-unlock.json";
/// Directory on the stick. Visible on purpose: the person who finds a stray
/// stick should be able to see whose it is, and the file is useless anyway.
const KEY_DIR: &str = "Arca";
const KEY_FILE_EXT: &str = "arcakey";
const KEY_FILE_VERSION: u32 = 1;
/// Domain separator for the derivation, so the same two random inputs could
/// never be repurposed for anything else.
const DERIVE_INFO: &[u8] = b"arca keyfile unlock v1";
/// AAD of the vault-key wrap kept in the sidecar.
const WRAP_AAD: &[u8] = b"arca/keyfile-unlock/v1";
/// A key file is a few hundred bytes. Anything bigger is not ours.
const MAX_KEY_FILE_BYTES: u64 = 4096;
/// How often the watcher looks for the file.
const POLL: Duration = Duration::from_secs(1);
/// A freshly inserted stick can be visible before its filesystem is ready to
/// mount. Try a few times before waiting for the next insertion.
const INSERT_RETRIES: u8 = 5;

// ── configuration next to the vault ────────────────────────────────────────

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    pub version: u32,
    /// The volume's id as the platform reported it at enrollment: a
    /// filesystem UUID on Linux (`/dev/disk/by-uuid/<this>`, used to mount),
    /// diskutil's VolumeUUID on macOS, the volume GUID path on Windows. For
    /// mounting and display; the key file's own id is what is trusted.
    #[serde(default)]
    pub volume_id: String,
    /// For the UI only.
    pub volume_label: String,
    /// Path of the key file relative to the volume's root.
    pub relative_path: String,
    /// Random id also written into the key file, so a wrong or stale file is
    /// reported as such instead of as a bad unwrap.
    pub file_id: String,
    /// The local half of the device key, hex. Lives only in this `0600` file.
    pepper: String,
    /// The vault key wrapped under the derived key. Local, like the pepper.
    wrapped_vault_key: AeadBlob,
    #[serde(default = "default_true")]
    pub lock_on_removal: bool,
    pub enrolled_at: u64,
}

fn default_true() -> bool {
    true
}

/// What the key file on the stick contains.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyFile {
    arca_keyfile: u32,
    id: String,
    secret: String,
}

/// Reported to the frontend, on the vault status and after every change.
#[derive(Clone, Serialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct KeyFileStatus {
    pub enrolled: bool,
    /// The key file is reachable right now.
    pub present: bool,
    pub volume_label: String,
    pub volume_id: String,
    pub lock_on_removal: bool,
}

/// A removable volume the user can pick at enrollment.
#[derive(Clone, Serialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct VolumeDto {
    pub id: String,
    pub label: String,
    pub device: String,
    pub size_bytes: u64,
    pub mounted: bool,
    /// The stick already carries an Arca key file, which enrollment adopts.
    pub has_key: bool,
}

fn config_path(store: &VaultStore) -> PathBuf {
    store.path().with_file_name(CONFIG_FILE)
}

pub fn load(store: &VaultStore) -> Result<Option<Config>, CmdError> {
    match std::fs::read(config_path(store)) {
        Ok(bytes) => serde_json::from_slice(&bytes).map(Some).map_err(|_| {
            failure("The USB key settings are unreadable. Set the key up again in Settings.")
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(failure("Could not read the USB key settings.")),
    }
}

fn write(store: &VaultStore, config: &Config) -> Result<(), CmdError> {
    let bytes = serde_json::to_vec_pretty(config)
        .map_err(|_| failure("Could not encode the USB key settings."))?;
    // `write_atomic` restricts the file to the owner: the pepper lives here.
    vault_store::write_atomic(&config_path(store), &bytes)
        .map_err(|_| failure("Could not save the USB key settings."))
}

/// Whether a key file is enrolled for this vault.
pub fn enrolled(store: &VaultStore) -> bool {
    config_path(store).exists()
}

/// `None` when no key file is enrolled.
pub fn status(store: &VaultStore) -> Option<KeyFileStatus> {
    let config = load(store).ok().flatten()?;
    Some(status_of(&config))
}

fn status_of(config: &Config) -> KeyFileStatus {
    KeyFileStatus {
        enrolled: true,
        present: present(config),
        volume_label: config.volume_label.clone(),
        volume_id: config.volume_id.clone(),
        lock_on_removal: config.lock_on_removal,
    }
}

fn failure(message: &str) -> CmdError {
    CmdError::new("keyfile", message)
}
fn missing() -> CmdError {
    CmdError::new(
        "keyfile_missing",
        "Plug in your USB key, or enter your master password.",
    )
}

// ── the key itself ─────────────────────────────────────────────────────────

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Option<Zeroizing<Vec<u8>>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect::<Option<Vec<u8>>>()
        .map(Zeroizing::new)
}

/// The device key: HMAC-SHA256 keyed by the local pepper over the stick's
/// secret. Both inputs are 32 uniformly random bytes, so this is a KDF in the
/// extract sense only; the label keeps the output bound to this use.
fn derive(pepper: &[u8], secret: &[u8]) -> Result<SymmetricKey, CmdError> {
    use hmac::Mac;
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(pepper)
        .map_err(|_| failure("The USB key settings are invalid."))?;
    mac.update(DERIVE_INFO);
    mac.update(secret);
    let out = mac.finalize().into_bytes();
    let mut bytes = [0u8; KEY_LEN];
    bytes.copy_from_slice(&out[..KEY_LEN]);
    Ok(SymmetricKey::from_bytes(bytes))
}

/// Parse a key file. `expect_id` binds it to one enrollment; `None` accepts
/// any well-formed file (adoption at enrollment).
fn read_key_file(
    path: &Path,
    expect_id: Option<&str>,
) -> Result<(String, Zeroizing<Vec<u8>>), CmdError> {
    let meta = std::fs::metadata(path).map_err(|_| missing())?;
    if !meta.is_file() || meta.len() > MAX_KEY_FILE_BYTES {
        return Err(failure("The file on the USB key is not an Arca key file."));
    }
    let bytes = Zeroizing::new(std::fs::read(path).map_err(|_| missing())?);
    let file: KeyFile = serde_json::from_slice(&bytes)
        .map_err(|_| failure("The file on the USB key is not an Arca key file."))?;
    if file.arca_keyfile != KEY_FILE_VERSION {
        return Err(failure(
            "This key file was made by a newer Arca. Update the app.",
        ));
    }
    if expect_id.is_some_and(|id| id != file.id) {
        return Err(failure(
            "The key file on this USB stick belongs to a different enrollment. Set the key up again in Settings.",
        ));
    }
    let secret = unhex(&file.secret)
        .filter(|s| s.len() == KEY_LEN)
        .ok_or_else(|| failure("The key file on the USB stick is damaged."))?;
    Ok((file.id, secret))
}

/// Derive this machine's device key from the enrolled file at `path`.
fn key_from_file(path: &Path, config: &Config) -> Result<SymmetricKey, CmdError> {
    let (_, secret) = read_key_file(path, Some(&config.file_id))?;
    let pepper = unhex(&config.pepper)
        .filter(|p| p.len() == KEY_LEN)
        .ok_or_else(|| failure("The USB key settings are invalid."))?;
    derive(&pepper, &secret)
}

/// Write the key file the way a FAT stick allows: no permission bits, a
/// sibling temp file, fsync, rename, fsync the directory.
fn write_key_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let dir = path
        .parent()
        .ok_or_else(|| std::io::Error::other("key file has no directory"))?;
    std::fs::create_dir_all(dir)?;
    let tmp = path.with_extension("tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

/// Arca key files on a volume root, whichever machine made them.
fn key_files_at(root: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(root.join(KEY_DIR)) else {
        return Vec::new();
    };
    let mut found: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some(KEY_FILE_EXT))
        .collect();
    found.sort();
    found
}

// ── finding the file ───────────────────────────────────────────────────────

/// Where the enrolled key file is right now, if any mounted volume has it.
/// Cheap — a handful of `stat`s — so the watcher can call it every second.
fn find_key_file(config: &Config) -> Option<PathBuf> {
    volume::roots()
        .into_iter()
        .map(|root| root.join(&config.relative_path))
        .find(|p| p.is_file())
}

/// Is the stick here? Linux can see the device node before the desktop mounts
/// it; everywhere the mounted file is the answer.
fn present(config: &Config) -> bool {
    volume::device_present(&config.volume_id) || find_key_file(config).is_some()
}

/// The key file, mounting the stick on Linux if the desktop has not.
fn locate(config: &Config) -> Result<PathBuf, CmdError> {
    if let Some(path) = find_key_file(config) {
        return Ok(path);
    }
    let root = volume::mount_by_id(&config.volume_id)?.ok_or_else(missing)?;
    let path = root.join(&config.relative_path);
    if path.is_file() {
        Ok(path)
    } else {
        Err(missing())
    }
}

// ── unlock ─────────────────────────────────────────────────────────────────

/// Open the vault with the key file if it is enrolled and plugged in.
///
/// `Ok(true)` means this call opened the vault; `Ok(false)` that it was open
/// already. The slow parts — finding, mounting and reading the stick — run
/// with no lock held, so a slow mount never stalls the window or the bridge.
pub fn try_unlock(state: &Mutex<AppState>) -> Result<bool, CmdError> {
    let config = {
        let st = state.lock().map_err(|_| failure("Vault unavailable."))?;
        if st.vault.as_ref().is_some_and(|v| v.is_unlocked()) {
            return Ok(false);
        }
        load(&st.store)?.ok_or_else(|| {
            CmdError::new(
                "keyfile_not_enrolled",
                "No USB key is set up for this vault.",
            )
        })?
    };
    let path = locate(&config)?;
    unlock_from(state, &config, &path)
}

fn unlock_from(
    state: &Mutex<AppState>,
    config: &Config,
    key_path: &Path,
) -> Result<bool, CmdError> {
    let key = key_from_file(key_path, config)?;
    let mut st = state.lock().map_err(|_| failure("Vault unavailable."))?;
    if st.vault.is_none() && st.store.exists() {
        st.vault = Some(st.store.load()?);
    }
    let vault = st.vault_mut()?;
    if vault.is_unlocked() {
        return Ok(false);
    }
    if !vault.wrapped_key_matches(&key, &config.wrapped_vault_key, WRAP_AAD) {
        return Err(CmdError::new(
            "keyfile_stale",
            "This USB key no longer matches the vault. Unlock with your master password once to repair it.",
        ));
    }
    vault.unlock_with_wrapped_key(&key, &config.wrapped_vault_key, WRAP_AAD)?;
    st.touch();
    Ok(true)
}

/// For callers that only want the side effect and a yes/no: the bridge, the
/// watcher. Never errors, never prompts.
pub fn unlock_if_locked(state: &Mutex<AppState>) -> bool {
    enrolled_quick(state) && matches!(try_unlock(state), Ok(true))
}

/// A cheap pre-check so unenrolled installations pay one `stat` per request,
/// not a config parse and a volume scan.
fn enrolled_quick(state: &Mutex<AppState>) -> bool {
    state.lock().map(|st| enrolled(&st.store)).unwrap_or(false)
}

/// After a master-password unlock: if the stick is here and the sidecar's wrap
/// no longer opens this vault (a restored backup, a vault adopted from a
/// peer), re-wrap so the next unlock is silent again. Only an already-mounted
/// file — this runs under the state lock and must not wait on a mount.
pub fn heal(st: &mut AppState) {
    let Ok(Some(mut config)) = load(&st.store) else {
        return;
    };
    let Some(path) = find_key_file(&config) else {
        return;
    };
    let Ok(key) = key_from_file(&path, &config) else {
        return;
    };
    let Some(vault) = st.vault.as_ref().filter(|v| v.is_unlocked()) else {
        return;
    };
    if vault.wrapped_key_matches(&key, &config.wrapped_vault_key, WRAP_AAD) {
        return;
    }
    if let Ok(wrapped) = vault.wrap_vault_key(&key, WRAP_AAD) {
        config.wrapped_vault_key = wrapped;
        let _ = write(&st.store, &config);
    }
}

// ── enroll / revoke ────────────────────────────────────────────────────────

/// Bind the vault to the key file on volume `id`, writing one if the stick
/// has none. The vault must be unlocked; the caller has already re-confirmed
/// the master password.
pub fn enroll(
    state: &Mutex<AppState>,
    id: &str,
    lock_on_removal: bool,
) -> Result<KeyFileStatus, CmdError> {
    let vol = volume::candidates()?
        .into_iter()
        .find(|v| v.id == id)
        .ok_or_else(|| {
            CmdError::new(
                "keyfile_missing",
                "That USB stick is not plugged in any more.",
            )
        })?;
    let root = volume::ensure_mounted(&vol)?;
    enroll_at(state, &vol.id, &vol.label, &root, lock_on_removal)
}

fn enroll_at(
    state: &Mutex<AppState>,
    volume_id: &str,
    label: &str,
    root: &Path,
    lock_on_removal: bool,
) -> Result<KeyFileStatus, CmdError> {
    {
        let st = state.lock().map_err(|_| failure("Vault unavailable."))?;
        if !st.vault()?.is_unlocked() {
            return Err(CmdError::new("locked", "Unlock the vault first."));
        }
    }

    // One file per stick, shared by every computer that enrolls it. Adopt the
    // existing one when there is exactly one; several means someone has been
    // copying files around, and a fresh one is the honest answer.
    let existing = key_files_at(root);
    let mut created: Option<PathBuf> = None;
    let (relative_path, file_id, secret) = match existing.as_slice() {
        [one] if read_key_file(one, None).is_ok() => {
            let (id, secret) = read_key_file(one, None)?;
            let name = one.file_name().and_then(|n| n.to_str()).unwrap_or_default();
            (format!("{KEY_DIR}/{name}"), id, secret)
        }
        _ => {
            // `SymmetricKey::generate` is the crate's CSPRNG path into locked
            // memory; the value is used as bytes, not as a key.
            let fresh = SymmetricKey::generate()?;
            let secret = Zeroizing::new(fresh.as_bytes().to_vec());
            let file_id = uuid::Uuid::new_v4().simple().to_string();
            let relative_path = format!("{KEY_DIR}/{file_id}.{KEY_FILE_EXT}");
            let file = KeyFile {
                arca_keyfile: KEY_FILE_VERSION,
                id: file_id.clone(),
                secret: hex(&secret),
            };
            let bytes = serde_json::to_vec_pretty(&file)
                .map_err(|_| failure("Could not encode the key file."))?;
            let path = root.join(&relative_path);
            write_key_file(&path, &bytes).map_err(|e| {
                failure(&format!(
                    "Could not write the key file to the USB stick: {e}"
                ))
            })?;
            // Read back through the same path an unlock takes, so a stick that
            // lies about having written fails here and not tomorrow.
            let read_back = read_key_file(&path, Some(&file_id)).ok().map(|(_, s)| s);
            if read_back.as_deref().map(|s| s.as_slice()) != Some(secret.as_slice()) {
                let _ = std::fs::remove_file(&path);
                return Err(failure(
                    "The key file did not read back correctly. Try another USB stick.",
                ));
            }
            created = Some(path);
            (relative_path, file_id, secret)
        }
    };

    let pepper = SymmetricKey::generate()?;
    let key = derive(pepper.as_bytes(), &secret)?;

    let mut st = state.lock().map_err(|_| failure("Vault unavailable."))?;
    let wrapped = match st
        .vault()
        .and_then(|v| v.wrap_vault_key(&key, WRAP_AAD).map_err(Into::into))
    {
        Ok(w) => w,
        Err(e) => {
            if let Some(p) = created {
                let _ = std::fs::remove_file(p);
            }
            return Err(e);
        }
    };
    let config = Config {
        version: 1,
        volume_id: volume_id.to_owned(),
        volume_label: label.to_owned(),
        relative_path,
        file_id,
        pepper: hex(pepper.as_bytes()),
        wrapped_vault_key: wrapped,
        lock_on_removal,
        enrolled_at: crate::state::now_secs(),
    };
    if let Err(e) = write(&st.store, &config) {
        if let Some(p) = created {
            let _ = std::fs::remove_file(p);
        }
        return Err(e);
    }
    st.touch();
    Ok(status_of(&config))
}

/// Forget the key on this computer: delete the sidecar (pepper and wrap). The
/// file on the stick stays — other computers may be enrolled with it, and it
/// opens nothing here any more. The vault must be unlocked.
pub fn revoke(state: &Mutex<AppState>) -> Result<(), CmdError> {
    let mut st = state.lock().map_err(|_| failure("Vault unavailable."))?;
    if !st.vault()?.is_unlocked() {
        return Err(CmdError::new("locked", "Unlock the vault first."));
    }
    match std::fs::remove_file(config_path(&st.store)) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(failure("Could not remove the USB key settings.")),
    }
    st.touch();
    Ok(())
}

pub fn configure(
    state: &Mutex<AppState>,
    lock_on_removal: bool,
) -> Result<KeyFileStatus, CmdError> {
    let st = state.lock().map_err(|_| failure("Vault unavailable."))?;
    let mut config = load(&st.store)?.ok_or_else(|| {
        CmdError::new(
            "keyfile_not_enrolled",
            "No USB key is set up for this vault.",
        )
    })?;
    config.lock_on_removal = lock_on_removal;
    write(&st.store, &config)?;
    Ok(status_of(&config))
}

// ── the watcher ────────────────────────────────────────────────────────────

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Action {
    Nothing,
    Lock,
    Unlock,
}

/// The watcher's whole policy, as a function of what it can see.
///
/// Insertion (or the stick already being in when Arca starts) opens a locked
/// vault; removal locks an open one when the user left that on. Nothing else
/// — in particular an idle lock with the stick still inserted stays locked
/// until something asks (the window gaining focus, a browser request): the
/// stick is standing permission to open, not a reason to sit open.
fn decide(
    was_present: Option<bool>,
    present: bool,
    unlocked: bool,
    lock_on_removal: bool,
) -> Action {
    match (was_present, present) {
        (Some(true), false) if lock_on_removal && unlocked => Action::Lock,
        (Some(false) | None, true) if !unlocked => Action::Unlock,
        _ => Action::Nothing,
    }
}

fn lock_vault(state: &Mutex<AppState>) -> bool {
    let Ok(mut st) = state.lock() else {
        return false;
    };
    let locked = st
        .vault
        .as_mut()
        .filter(|v| v.is_unlocked())
        .is_some_and(|v| v.lock().is_ok());
    if locked {
        st.unlock_generation = st.unlock_generation.wrapping_add(1);
    }
    locked
}

/// Polls for the key file once a second. Locks on removal, unlocks on
/// insertion, and tells the webview about both exactly like the idle lock.
pub fn watch(app: AppHandle) {
    let mut was_present: Option<bool> = None;
    let mut retries: u8 = 0;
    loop {
        std::thread::sleep(POLL);
        let state = app.state::<Mutex<AppState>>();
        let config = {
            let Ok(st) = state.lock() else { continue };
            load(&st.store).ok().flatten()
        };
        let Some(config) = config else {
            was_present = None;
            continue;
        };
        let here = present(&config);
        let unlocked = state
            .lock()
            .map(|st| st.vault.as_ref().is_some_and(|v| v.is_unlocked()))
            .unwrap_or(false);
        match decide(was_present, here, unlocked, config.lock_on_removal) {
            Action::Lock => {
                if lock_vault(&state) {
                    let _ = app.emit("vault-locked", "keyfile-removed");
                }
            }
            Action::Unlock => match try_unlock(&state) {
                Ok(true) => {
                    let _ = app.emit("vault-unlocked", ());
                    crate::commands::publish_identities(&app);
                }
                Ok(false) => {}
                Err(_) if retries < INSERT_RETRIES => {
                    // Not present yet as far as the policy is concerned, so the
                    // next tick tries again — a bounded number of times.
                    retries += 1;
                    continue;
                }
                Err(_) => {}
            },
            Action::Nothing => {}
        }
        retries = 0;
        was_present = Some(here);
    }
}

// ── tauri commands ─────────────────────────────────────────────────────────

#[tauri::command]
pub fn keyfile_candidates() -> Result<Vec<VolumeDto>, CmdError> {
    Ok(volume::candidates()?
        .into_iter()
        .map(|v| VolumeDto {
            has_key: v
                .root
                .as_deref()
                .is_some_and(|r| !key_files_at(r).is_empty()),
            id: v.id,
            label: v.label,
            device: v.device,
            size_bytes: v.size,
            mounted: v.root.is_some(),
        })
        .collect())
}

#[tauri::command]
pub async fn keyfile_enroll(
    app: AppHandle,
    volume_id: String,
    lock_on_removal: bool,
    current_password: Option<String>,
) -> Result<KeyFileStatus, CmdError> {
    let authorization = crate::reauth::authorize(
        &app,
        "set up a USB key that unlocks this vault",
        current_password,
    )
    .await?;
    let worker = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let state = worker.state::<Mutex<AppState>>();
        {
            let st = state.lock().map_err(|_| failure("Vault unavailable."))?;
            authorization.validate(&st)?;
        }
        enroll(&state, &volume_id, lock_on_removal)
    })
    .await
    .map_err(|_| failure("The enrollment task failed."))?
}

#[tauri::command]
pub async fn keyfile_revoke(
    app: AppHandle,
    current_password: Option<String>,
) -> Result<(), CmdError> {
    let authorization =
        crate::reauth::authorize(&app, "remove the USB key from this vault", current_password)
            .await?;
    let worker = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let state = worker.state::<Mutex<AppState>>();
        {
            let st = state.lock().map_err(|_| failure("Vault unavailable."))?;
            authorization.validate(&st)?;
        }
        revoke(&state)
    })
    .await
    .map_err(|_| failure("The removal task failed."))?
}

#[tauri::command]
pub fn keyfile_configure(
    state: tauri::State<'_, Mutex<AppState>>,
    lock_on_removal: bool,
) -> Result<KeyFileStatus, CmdError> {
    configure(state.inner(), lock_on_removal)
}

/// The lock screen's button and its automatic attempt on focus.
#[tauri::command]
pub async fn keyfile_unlock(app: AppHandle) -> Result<(), CmdError> {
    let worker = app.clone();
    let opened = tauri::async_runtime::spawn_blocking(move || {
        let state = worker.state::<Mutex<AppState>>();
        try_unlock(&state)
    })
    .await
    .map_err(|_| failure("The unlock task failed."))??;
    if opened {
        crate::commands::publish_identities(&app);
        crate::commands::kick_sync(&app);
    }
    Ok(())
}

// ── volumes ────────────────────────────────────────────────────────────────
//
// Three things per platform: the roots to look for a key file under (cheap,
// polled), the removable volumes to offer at enrollment (slow is fine), and —
// Linux only — mounting a stick the desktop left unmounted.

pub(crate) mod volume {
    use super::CmdError;
    use std::path::{Path, PathBuf};

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Volume {
        pub id: String,
        pub label: String,
        pub device: String,
        pub root: Option<PathBuf>,
        pub size: u64,
    }

    /// Every directory a removable volume can be mounted under, plus the
    /// volumes actually mounted there. Each entry costs one `stat` per poll.
    pub fn roots() -> Vec<PathBuf> {
        roots_under(&root_parents())
    }

    #[cfg(target_os = "linux")]
    fn root_parents() -> Vec<PathBuf> {
        let mut parents = vec![PathBuf::from("/media")];
        if let Ok(users) = std::fs::read_dir("/run/media") {
            parents.extend(users.flatten().map(|e| e.path()));
        }
        // `/media/<user>` on Debian-style desktops.
        if let Ok(users) = std::fs::read_dir("/media") {
            parents.extend(users.flatten().map(|e| e.path()).filter(|p| p.is_dir()));
        }
        parents
    }
    #[cfg(target_os = "macos")]
    fn root_parents() -> Vec<PathBuf> {
        vec![PathBuf::from("/Volumes")]
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    fn root_parents() -> Vec<PathBuf> {
        Vec::new()
    }

    /// The roots under a set of parents — and on Windows the drive letters,
    /// which have no parent.
    pub(super) fn roots_under(parents: &[PathBuf]) -> Vec<PathBuf> {
        let mut out: Vec<PathBuf> = Vec::new();
        for parent in parents {
            if let Ok(entries) = std::fs::read_dir(parent) {
                out.extend(entries.flatten().map(|e| e.path()).filter(|p| p.is_dir()));
            }
        }
        #[cfg(target_os = "windows")]
        {
            // C: is the system drive; A: and B: still make some machines wait
            // on a floppy controller that is not there.
            out.extend((b'D'..=b'Z').map(|l| PathBuf::from(format!("{}:\\", l as char))));
        }
        out.sort();
        out.dedup();
        out
    }

    // ── Linux ──────────────────────────────────────────────────────────

    #[cfg(target_os = "linux")]
    fn by_uuid_path(uuid: &str) -> Option<PathBuf> {
        // Defensive: the id comes from our own config, but it becomes a path.
        if uuid.is_empty() || uuid.contains('/') || uuid.contains("..") {
            return None;
        }
        Some(Path::new("/dev/disk/by-uuid").join(uuid))
    }

    /// Linux sees the device node before the desktop mounts it. Elsewhere the
    /// mounted file is the only signal, and `false` here defers to it.
    #[cfg(target_os = "linux")]
    pub fn device_present(id: &str) -> bool {
        by_uuid_path(id).is_some_and(|p| p.exists())
    }
    #[cfg(not(target_os = "linux"))]
    pub fn device_present(_id: &str) -> bool {
        false
    }

    /// `/proc/self/mountinfo` line format: `… <mountpoint> … - <fstype> <source> …`.
    /// Spaces and friends inside paths are octal-escaped.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(super) fn mountpoint_for(device: &Path, mountinfo: &str) -> Option<PathBuf> {
        for line in mountinfo.lines() {
            let Some((left, right)) = line.split_once(" - ") else {
                continue;
            };
            let left: Vec<&str> = left.split(' ').collect();
            let right: Vec<&str> = right.split(' ').collect();
            if left.len() < 5 || right.len() < 2 {
                continue;
            }
            if Path::new(&unescape(right[1])) == device {
                return Some(PathBuf::from(unescape(left[4])));
            }
        }
        None
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    fn unescape(s: &str) -> String {
        let bytes = s.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'\\' && i + 3 < bytes.len() {
                if let Ok(code) = u8::from_str_radix(&s[i + 1..i + 4], 8) {
                    out.push(code);
                    i += 4;
                    continue;
                }
            }
            out.push(bytes[i]);
            i += 1;
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    /// `lsblk -J -b`: nested (`children`) or flat, `rm`/`hotplug` as bool or
    /// as the "1"/"0" strings older util-linux printed.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(super) fn parse_lsblk(json: &str) -> Vec<Volume> {
        fn flag(v: &serde_json::Value) -> bool {
            match v {
                serde_json::Value::Bool(b) => *b,
                serde_json::Value::String(s) => s == "1" || s == "true",
                serde_json::Value::Number(n) => n.as_u64() == Some(1),
                _ => false,
            }
        }
        fn walk(node: &serde_json::Value, out: &mut Vec<Volume>) {
            let get = |k: &str| node.get(k).and_then(|v| v.as_str()).map(str::to_owned);
            let removable =
                node.get("rm").is_some_and(flag) || node.get("hotplug").is_some_and(flag);
            let kind = get("type").unwrap_or_default();
            let fstype = get("fstype").unwrap_or_default();
            if let (Some(uuid), Some(path)) = (get("uuid"), get("path")) {
                if removable
                    && !uuid.is_empty()
                    && (kind == "part" || kind == "disk")
                    && !fstype.is_empty()
                    && fstype != "swap"
                    && !fstype.contains("_member")
                {
                    out.push(Volume {
                        label: get("label")
                            .filter(|l| !l.is_empty())
                            .unwrap_or_else(|| uuid.clone()),
                        id: uuid,
                        device: path,
                        root: get("mountpoint")
                            .filter(|m| !m.is_empty())
                            .map(PathBuf::from),
                        size: node.get("size").and_then(|s| s.as_u64()).unwrap_or(0),
                    });
                }
            }
            if let Some(children) = node.get("children").and_then(|c| c.as_array()) {
                for child in children {
                    walk(child, out);
                }
            }
        }
        let mut out = Vec::new();
        if let Ok(root) = serde_json::from_str::<serde_json::Value>(json) {
            if let Some(devices) = root.get("blockdevices").and_then(|d| d.as_array()) {
                for d in devices {
                    walk(d, &mut out);
                }
            }
        }
        out
    }

    #[cfg(target_os = "linux")]
    pub fn candidates() -> Result<Vec<Volume>, CmdError> {
        let out = std::process::Command::new("lsblk")
            .args([
                "-J",
                "-b",
                "-o",
                "PATH,UUID,LABEL,FSTYPE,MOUNTPOINT,RM,HOTPLUG,SIZE,TYPE",
            ])
            .output()
            .map_err(|_| super::failure("Could not list USB drives (lsblk is missing)."))?;
        Ok(parse_lsblk(&String::from_utf8_lossy(&out.stdout)))
    }

    /// Mount through udisks2 if the desktop has not. Removable media in an
    /// active local session needs no password under the default polkit rules;
    /// `--no-user-interaction` turns any exception into an error, never a
    /// dialog from a background thread.
    #[cfg(target_os = "linux")]
    pub fn ensure_mounted(vol: &Volume) -> Result<PathBuf, CmdError> {
        if let Some(m) = &vol.root {
            return Ok(m.clone());
        }
        let out = std::process::Command::new("udisksctl")
            .args(["mount", "--no-user-interaction", "-b", &vol.device])
            .output()
            .map_err(|_| super::failure("Could not mount the USB key (udisksctl is missing)."))?;
        let stderr = String::from_utf8_lossy(&out.stderr);
        if !out.status.success() && !stderr.contains("AlreadyMounted") {
            return Err(super::failure(&format!(
                "Could not mount the USB key: {}",
                stderr.trim()
            )));
        }
        let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
        let device =
            std::fs::canonicalize(&vol.device).unwrap_or_else(|_| PathBuf::from(&vol.device));
        mountpoint_for(&device, &mountinfo).ok_or_else(|| {
            super::failure("The USB key mounted, but its mount point could not be found.")
        })
    }

    /// The enrolled stick is attached but not mounted (Linux): mount it and
    /// return its root. `Ok(None)` when it is not attached.
    #[cfg(target_os = "linux")]
    pub fn mount_by_id(id: &str) -> Result<Option<PathBuf>, CmdError> {
        let Some(link) = by_uuid_path(id).filter(|p| p.exists()) else {
            return Ok(None);
        };
        let device = std::fs::canonicalize(&link).map_err(|_| super::missing())?;
        let vol = Volume {
            id: id.to_owned(),
            label: id.to_owned(),
            device: device.display().to_string(),
            root: None,
            size: 0,
        };
        ensure_mounted(&vol).map(Some)
    }
    #[cfg(not(target_os = "linux"))]
    pub fn mount_by_id(_id: &str) -> Result<Option<PathBuf>, CmdError> {
        Ok(None)
    }

    // ── macOS ──────────────────────────────────────────────────────────

    /// `mount(8)` lines: `/dev/disk4s1 on /Volumes/ARCA (msdos, local, …)`.
    /// Only volumes under /Volumes.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(super) fn parse_macos_mounts(out: &str) -> Vec<(String, PathBuf)> {
        out.lines()
            .filter_map(|line| {
                let (dev, rest) = line.split_once(" on ")?;
                let (mount, _) = rest.rsplit_once(" (")?;
                (dev.starts_with("/dev/disk") && mount.starts_with("/Volumes/"))
                    .then(|| (dev.to_owned(), PathBuf::from(mount)))
            })
            .collect()
    }

    /// One value out of `diskutil info -plist`: the element following
    /// `<key>NAME</key>`. Booleans come back as "true"/"false".
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(super) fn plist_value(xml: &str, key: &str) -> Option<String> {
        let needle = format!("<key>{key}</key>");
        let after = &xml[xml.find(&needle)? + needle.len()..];
        let after = after.trim_start();
        if after.starts_with("<true/>") {
            return Some("true".into());
        }
        if after.starts_with("<false/>") {
            return Some("false".into());
        }
        for tag in ["string", "integer"] {
            let open = format!("<{tag}>");
            if let Some(rest) = after.strip_prefix(open.as_str()) {
                let end = rest.find(&format!("</{tag}>"))?;
                return Some(rest[..end].to_owned());
            }
        }
        None
    }

    #[cfg(target_os = "macos")]
    pub fn candidates() -> Result<Vec<Volume>, CmdError> {
        let mounts = std::process::Command::new("mount")
            .output()
            .map_err(|_| super::failure("Could not list volumes."))?;
        let mut out = Vec::new();
        for (dev, root) in parse_macos_mounts(&String::from_utf8_lossy(&mounts.stdout)) {
            let Ok(info) = std::process::Command::new("diskutil")
                .args(["info", "-plist", &dev])
                .output()
            else {
                continue;
            };
            let xml = String::from_utf8_lossy(&info.stdout);
            let external = plist_value(&xml, "RemovableMedia").as_deref() == Some("true")
                || plist_value(&xml, "Ejectable").as_deref() == Some("true")
                || plist_value(&xml, "Internal").as_deref() == Some("false");
            if !external {
                continue;
            }
            let label = plist_value(&xml, "VolumeName")
                .filter(|l| !l.is_empty())
                .or_else(|| root.file_name().map(|n| n.to_string_lossy().into_owned()))
                .unwrap_or_else(|| dev.clone());
            out.push(Volume {
                id: plist_value(&xml, "VolumeUUID").unwrap_or_else(|| root.display().to_string()),
                label,
                device: dev,
                size: plist_value(&xml, "TotalSize")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0),
                root: Some(root),
            });
        }
        Ok(out)
    }

    #[cfg(target_os = "macos")]
    pub fn ensure_mounted(vol: &Volume) -> Result<PathBuf, CmdError> {
        vol.root
            .clone()
            .ok_or_else(|| super::failure("Mount the USB stick in Finder first."))
    }

    // ── Windows ────────────────────────────────────────────────────────

    /// `Get-Volume … | ConvertTo-Json`: an array, or a bare object when there
    /// is exactly one.
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    pub(super) fn parse_windows_volumes(json: &str) -> Vec<Volume> {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(json) else {
            return Vec::new();
        };
        let items: Vec<serde_json::Value> = match value {
            serde_json::Value::Array(a) => a,
            other => vec![other],
        };
        items
            .iter()
            .filter_map(|v| {
                let letter = v.get("DriveLetter")?;
                let letter = match letter {
                    serde_json::Value::String(s) => s.chars().next()?,
                    // PowerShell serialises a [char] as its code point.
                    serde_json::Value::Number(n) => char::from_u32(n.as_u64()? as u32)?,
                    _ => return None,
                };
                if !letter.is_ascii_alphabetic() {
                    return None;
                }
                let root = PathBuf::from(format!("{}:\\", letter.to_ascii_uppercase()));
                let label = v
                    .get("FileSystemLabel")
                    .and_then(|l| l.as_str())
                    .filter(|l| !l.is_empty())
                    .map(str::to_owned)
                    .unwrap_or_else(|| format!("{}:", letter.to_ascii_uppercase()));
                Some(Volume {
                    id: v
                        .get("UniqueId")
                        .and_then(|u| u.as_str())
                        .filter(|u| !u.is_empty())
                        .map(str::to_owned)
                        .unwrap_or_else(|| root.display().to_string()),
                    label,
                    device: root.display().to_string(),
                    size: v.get("Size").and_then(|s| s.as_u64()).unwrap_or(0),
                    root: Some(root),
                })
            })
            .collect()
    }

    #[cfg(target_os = "windows")]
    pub fn candidates() -> Result<Vec<Volume>, CmdError> {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let out = std::process::Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Get-Volume | Where-Object { $_.DriveType -eq 'Removable' -and $_.DriveLetter } | Select-Object DriveLetter,FileSystemLabel,Size,UniqueId | ConvertTo-Json -Compress",
            ])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map_err(|_| super::failure("Could not list USB drives."))?;
        Ok(parse_windows_volumes(&String::from_utf8_lossy(&out.stdout)))
    }

    #[cfg(target_os = "windows")]
    pub fn ensure_mounted(vol: &Volume) -> Result<PathBuf, CmdError> {
        vol.root
            .clone()
            .ok_or_else(|| super::failure("The USB stick has no drive letter."))
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    pub fn candidates() -> Result<Vec<Volume>, CmdError> {
        Ok(Vec::new())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    pub fn ensure_mounted(_vol: &Volume) -> Result<PathBuf, CmdError> {
        Err(CmdError::new(
            "keyfile_unsupported",
            "USB key unlock is not available here.",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_core::{KdfParams, Vault};

    fn fast_params() -> KdfParams {
        let mut params = KdfParams::new_default().unwrap();
        params.m_cost_kib = 256;
        params.t_cost = 1;
        params.p_cost = 1;
        params
    }

    fn unlocked_state(dir: &Path) -> Mutex<AppState> {
        let store = VaultStore::new(dir.join("vault"), "test", "keyfile");
        let (clipboard, _) = crate::clipboard::ClipboardManager::memory();
        let vault = Vault::create("correct-password", fast_params()).unwrap();
        store.save(&vault).unwrap();
        Mutex::new(AppState::new(store, Some(vault), clipboard))
    }

    fn lock(state: &Mutex<AppState>) {
        state
            .lock()
            .unwrap()
            .vault
            .as_mut()
            .unwrap()
            .lock()
            .unwrap();
    }
    fn is_unlocked(state: &Mutex<AppState>) -> bool {
        state.lock().unwrap().vault.as_ref().unwrap().is_unlocked()
    }
    fn config_of(state: &Mutex<AppState>) -> Config {
        load(&state.lock().unwrap().store).unwrap().unwrap()
    }

    #[test]
    fn derivation_is_deterministic_and_bound_to_both_halves() {
        let a = derive(&[1u8; 32], &[2u8; 32]).unwrap();
        assert_eq!(a, derive(&[1u8; 32], &[2u8; 32]).unwrap());
        assert_ne!(a, derive(&[9u8; 32], &[2u8; 32]).unwrap());
        assert_ne!(a, derive(&[1u8; 32], &[9u8; 32]).unwrap());
    }

    #[test]
    fn hex_round_trips_and_rejects_garbage() {
        let bytes: Vec<u8> = (0..=255).collect();
        assert_eq!(unhex(&hex(&bytes)).unwrap().as_slice(), bytes.as_slice());
        assert!(unhex("abc").is_none());
        assert!(unhex("zz").is_none());
    }

    #[test]
    fn enroll_then_unlock_from_the_stick_and_not_without_it() {
        let dir = tempfile::tempdir().unwrap();
        let stick = tempfile::tempdir().unwrap();
        let state = unlocked_state(dir.path());

        let status = enroll_at(&state, "4899-9740", "ARCA", stick.path(), true).unwrap();
        assert!(status.enrolled && status.lock_on_removal);
        assert_eq!(status.volume_label, "ARCA");
        let config = config_of(&state);
        assert!(enrolled(&state.lock().unwrap().store));
        let key_path = stick.path().join(&config.relative_path);
        assert!(key_path.is_file());
        // The header is not involved: the biometric slot stays free.
        assert!(!state
            .lock()
            .unwrap()
            .vault
            .as_ref()
            .unwrap()
            .has_device_unlock());
        // The stick holds no pepper and the sidecar holds no secret.
        let on_stick = std::fs::read_to_string(&key_path).unwrap();
        assert!(!on_stick.contains(&config.pepper));
        let secret_hex = on_stick.split("\"secret\": \"").nth(1).unwrap()[..16].to_owned();
        let on_disk = std::fs::read_to_string(dir.path().join(CONFIG_FILE)).unwrap();
        assert!(!on_disk.contains(&secret_hex));

        // Lock, then open again with nothing but the file.
        lock(&state);
        assert!(unlock_from(&state, &config, &key_path).unwrap());
        assert!(is_unlocked(&state));
        // Already open: reported as such, not as a second unlock.
        assert!(!unlock_from(&state, &config, &key_path).unwrap());

        // The stick is gone: the missing code, nothing opened.
        lock(&state);
        let gone = tempfile::tempdir()
            .unwrap()
            .path()
            .join(&config.relative_path);
        assert_eq!(
            unlock_from(&state, &config, &gone).unwrap_err().code,
            "keyfile_missing"
        );
        assert!(!is_unlocked(&state));
    }

    #[test]
    fn a_second_computer_adopts_the_file_already_on_the_stick() {
        let stick = tempfile::tempdir().unwrap();
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let a = unlocked_state(dir_a.path());
        let b = unlocked_state(dir_b.path()); // a different vault entirely
        enroll_at(&a, "id", "ARCA", stick.path(), true).unwrap();
        enroll_at(&b, "id", "ARCA", stick.path(), true).unwrap();
        let (ca, cb) = (config_of(&a), config_of(&b));
        // One file, two machines, two peppers, two wraps.
        assert_eq!(key_files_at(stick.path()).len(), 1);
        assert_eq!(ca.relative_path, cb.relative_path);
        assert_eq!(ca.file_id, cb.file_id);
        assert_ne!(ca.pepper, cb.pepper);
        assert_ne!(
            ca.wrapped_vault_key.ciphertext,
            cb.wrapped_vault_key.ciphertext
        );
        let key_path = stick.path().join(&ca.relative_path);
        lock(&a);
        lock(&b);
        assert!(unlock_from(&a, &ca, &key_path).unwrap());
        assert!(unlock_from(&b, &cb, &key_path).unwrap());
        // …and neither machine's sidecar opens the other's vault.
        lock(&a);
        assert_eq!(
            unlock_from(&a, &cb, &key_path).unwrap_err().code,
            "keyfile_stale"
        );
    }

    #[test]
    fn several_files_on_a_stick_mean_a_fresh_one() {
        let stick = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(stick.path().join(KEY_DIR)).unwrap();
        for n in 0..2u8 {
            let other = KeyFile {
                arca_keyfile: 1,
                id: format!("other{n}"),
                secret: hex(&[n; 32]),
            };
            std::fs::write(
                stick
                    .path()
                    .join(KEY_DIR)
                    .join(format!("other{n}.{KEY_FILE_EXT}")),
                serde_json::to_vec(&other).unwrap(),
            )
            .unwrap();
        }
        let dir = tempfile::tempdir().unwrap();
        let state = unlocked_state(dir.path());
        enroll_at(&state, "id", "l", stick.path(), true).unwrap();
        assert_eq!(key_files_at(stick.path()).len(), 3);
        assert!(!config_of(&state).file_id.starts_with("other"));
    }

    #[test]
    fn a_foreign_or_damaged_key_file_is_named_not_treated_as_a_bad_password() {
        let dir = tempfile::tempdir().unwrap();
        let stick = tempfile::tempdir().unwrap();
        let state = unlocked_state(dir.path());
        enroll_at(&state, "u", "l", stick.path(), true).unwrap();
        let config = config_of(&state);
        let path = stick.path().join(&config.relative_path);

        let other = KeyFile {
            arca_keyfile: 1,
            id: "someone-else".into(),
            secret: hex(&[7u8; 32]),
        };
        std::fs::write(&path, serde_json::to_vec(&other).unwrap()).unwrap();
        assert_eq!(key_from_file(&path, &config).unwrap_err().code, "keyfile");

        std::fs::write(&path, b"not json").unwrap();
        assert_eq!(key_from_file(&path, &config).unwrap_err().code, "keyfile");

        std::fs::write(&path, vec![b'x'; 8192]).unwrap();
        assert_eq!(key_from_file(&path, &config).unwrap_err().code, "keyfile");

        let future = KeyFile {
            arca_keyfile: 99,
            id: config.file_id.clone(),
            secret: hex(&[7u8; 32]),
        };
        std::fs::write(&path, serde_json::to_vec(&future).unwrap()).unwrap();
        assert!(key_from_file(&path, &config)
            .unwrap_err()
            .message
            .contains("newer Arca"));
    }

    #[test]
    fn a_replaced_vault_is_stale_and_heals_after_a_password_unlock() {
        let dir = tempfile::tempdir().unwrap();
        let stick = tempfile::tempdir().unwrap();
        let state = unlocked_state(dir.path());
        enroll_at(&state, "u", "l", stick.path(), true).unwrap();
        let config = config_of(&state);
        let key_path = stick.path().join(&config.relative_path);

        // The vault is replaced — a restore, a peer's copy — with another key.
        {
            let mut st = state.lock().unwrap();
            let fresh = Vault::create("correct-password", fast_params()).unwrap();
            st.store.save(&fresh).unwrap();
            st.vault = Some(st.store.load().unwrap());
        }
        assert_eq!(
            unlock_from(&state, &config, &key_path).unwrap_err().code,
            "keyfile_stale"
        );

        // The master password opens it; `heal` re-wraps into the sidecar. The
        // test drives the inner step because `heal` looks on real roots.
        {
            let mut st = state.lock().unwrap();
            st.vault
                .as_mut()
                .unwrap()
                .unlock("correct-password")
                .unwrap();
            let key = key_from_file(&key_path, &config).unwrap();
            let mut fixed = config.clone();
            fixed.wrapped_vault_key = st
                .vault
                .as_ref()
                .unwrap()
                .wrap_vault_key(&key, WRAP_AAD)
                .unwrap();
            write(&st.store, &fixed).unwrap();
        }
        lock(&state);
        assert!(unlock_from(&state, &config_of(&state), &key_path).unwrap());
    }

    #[test]
    fn revoke_forgets_this_computer_and_leaves_the_stick_for_the_others() {
        let dir = tempfile::tempdir().unwrap();
        let stick = tempfile::tempdir().unwrap();
        let state = unlocked_state(dir.path());
        enroll_at(&state, "u", "l", stick.path(), false).unwrap();
        let config = config_of(&state);
        revoke(&state).unwrap();
        assert!(!enrolled(&state.lock().unwrap().store));
        assert!(is_unlocked(&state));
        assert!(stick.path().join(&config.relative_path).is_file());
        // Without the sidecar the file is just bytes.
        lock(&state);
        assert!(try_unlock(&state).is_err());
        assert!(!is_unlocked(&state));
    }

    #[test]
    fn configure_flips_lock_on_removal_only() {
        let dir = tempfile::tempdir().unwrap();
        let stick = tempfile::tempdir().unwrap();
        let state = unlocked_state(dir.path());
        assert_eq!(
            configure(&state, false).unwrap_err().code,
            "keyfile_not_enrolled"
        );
        enroll_at(&state, "u", "l", stick.path(), true).unwrap();
        let before = config_of(&state);
        assert!(!configure(&state, false).unwrap().lock_on_removal);
        let after = config_of(&state);
        assert_eq!(after.pepper, before.pepper);
        assert_eq!(after.file_id, before.file_id);
        assert_eq!(after.wrapped_vault_key, before.wrapped_vault_key);
        assert!(!after.lock_on_removal);
    }

    #[test]
    fn enrollment_needs_an_open_vault() {
        let dir = tempfile::tempdir().unwrap();
        let stick = tempfile::tempdir().unwrap();
        let state = unlocked_state(dir.path());
        lock(&state);
        assert_eq!(
            enroll_at(&state, "u", "l", stick.path(), true)
                .unwrap_err()
                .code,
            "locked"
        );
        assert!(!enrolled(&state.lock().unwrap().store));
        assert!(!stick.path().join(KEY_DIR).exists());
    }

    #[test]
    fn the_file_is_found_under_any_root() {
        let parent = tempfile::tempdir().unwrap();
        let stick = parent.path().join("ARCA");
        std::fs::create_dir_all(stick.join(KEY_DIR)).unwrap();
        std::fs::create_dir_all(parent.path().join("OTHER")).unwrap();
        std::fs::write(stick.join(KEY_DIR).join("abc.arcakey"), b"{}").unwrap();
        let roots = volume::roots_under(&[parent.path().to_path_buf()]);
        assert!(roots.contains(&stick));
        assert!(roots.contains(&parent.path().join("OTHER")));
        let hit = roots
            .iter()
            .map(|r| r.join("Arca/abc.arcakey"))
            .find(|p| p.is_file());
        assert_eq!(hit, Some(stick.join("Arca/abc.arcakey")));
        let none = volume::roots_under(&[PathBuf::from("/definitely/not/here")]);
        assert!(none.is_empty() || cfg!(target_os = "windows"));
    }

    #[test]
    fn watcher_policy() {
        // Inserted (or already in at startup) while locked: open.
        assert_eq!(decide(None, true, false, true), Action::Unlock);
        assert_eq!(decide(Some(false), true, false, true), Action::Unlock);
        // Inserted while already open: nothing to do.
        assert_eq!(decide(Some(false), true, true, true), Action::Nothing);
        // Removed while open: lock — unless the user turned that off.
        assert_eq!(decide(Some(true), false, true, true), Action::Lock);
        assert_eq!(decide(Some(true), false, true, false), Action::Nothing);
        // Removed while already locked, or steady state either way: nothing.
        assert_eq!(decide(Some(true), false, false, true), Action::Nothing);
        assert_eq!(decide(Some(true), true, false, true), Action::Nothing);
        assert_eq!(decide(Some(false), false, false, true), Action::Nothing);
        // Absent at startup: not a removal.
        assert_eq!(decide(None, false, true, true), Action::Nothing);
    }

    #[test]
    fn mountinfo_lookup_handles_escapes_and_misses() {
        let info = "\
36 35 8:1 / /run/media/frank/ESD\\040USB rw,nosuid - vfat /dev/sda1 rw,uid=1000
40 35 259:1 / /mnt/Data rw,relatime - ext4 /dev/nvme0n1p1 rw
41 35 0:50 / /proc rw - proc proc rw";
        assert_eq!(
            volume::mountpoint_for(Path::new("/dev/sda1"), info),
            Some(PathBuf::from("/run/media/frank/ESD USB"))
        );
        assert_eq!(volume::mountpoint_for(Path::new("/dev/sdb1"), info), None);
        assert_eq!(volume::mountpoint_for(Path::new("/dev/sda1"), ""), None);
    }

    #[test]
    fn lsblk_parsing_keeps_removable_filesystems_only() {
        let flat = r#"{"blockdevices": [
          {"path":"/dev/sda","uuid":null,"label":null,"fstype":null,"mountpoint":null,"rm":true,"hotplug":true,"size":64160400896,"type":"disk"},
          {"path":"/dev/sda1","uuid":"4899-9740","label":"ARCA","fstype":"vfat","mountpoint":null,"rm":true,"hotplug":true,"size":64158303232,"type":"part"},
          {"path":"/dev/zram0","uuid":"7201","label":"zram0","fstype":"swap","mountpoint":"[SWAP]","rm":false,"hotplug":false,"size":1,"type":"disk"},
          {"path":"/dev/nvme0n1p1","uuid":"83ba","label":"Data","fstype":"ext4","mountpoint":"/mnt/Data","rm":false,"hotplug":false,"size":1,"type":"part"}
        ]}"#;
        let vols = volume::parse_lsblk(flat);
        assert_eq!(vols.len(), 1);
        assert_eq!(vols[0].id, "4899-9740");
        assert_eq!(vols[0].label, "ARCA");
        assert_eq!(vols[0].device, "/dev/sda1");
        assert_eq!(vols[0].root, None);
        assert_eq!(vols[0].size, 64158303232);

        let nested = r#"{"blockdevices": [
          {"path":"/dev/sdb","uuid":null,"fstype":null,"rm":"1","hotplug":"1","size":"1000","type":"disk","children":[
            {"path":"/dev/sdb1","uuid":"AAAA-BBBB","label":null,"fstype":"exfat","mountpoint":"/run/media/frank/AAAA-BBBB","rm":"1","hotplug":"1","size":"999","type":"part"}
          ]}
        ]}"#;
        let vols = volume::parse_lsblk(nested);
        assert_eq!(vols.len(), 1);
        assert_eq!(vols[0].label, "AAAA-BBBB");
        assert_eq!(
            vols[0].root,
            Some(PathBuf::from("/run/media/frank/AAAA-BBBB"))
        );

        assert!(volume::parse_lsblk("nonsense").is_empty());
    }

    #[test]
    fn macos_mount_and_plist_parsing() {
        let mounts = "\
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
devfs on /dev (devfs, local, nobrowse)
/dev/disk3s5 on /System/Volumes/Data (apfs, local, journaled, nobrowse)
/dev/disk4s1 on /Volumes/ARCA (msdos, local, nodev, nosuid, noowners)
/dev/disk5s2 on /Volumes/Time Machine (apfs, local, journaled)";
        let found = volume::parse_macos_mounts(mounts);
        assert_eq!(
            found,
            vec![
                ("/dev/disk4s1".to_owned(), PathBuf::from("/Volumes/ARCA")),
                (
                    "/dev/disk5s2".to_owned(),
                    PathBuf::from("/Volumes/Time Machine")
                ),
            ]
        );

        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
	<key>Ejectable</key>
	<true/>
	<key>Internal</key>
	<false/>
	<key>TotalSize</key>
	<integer>64158303232</integer>
	<key>VolumeName</key>
	<string>ARCA</string>
	<key>VolumeUUID</key>
	<string>1A2B3C4D-0000-1111-2222-333344445555</string>
</dict></plist>"#;
        assert_eq!(
            volume::plist_value(xml, "Ejectable").as_deref(),
            Some("true")
        );
        assert_eq!(
            volume::plist_value(xml, "Internal").as_deref(),
            Some("false")
        );
        assert_eq!(
            volume::plist_value(xml, "TotalSize").as_deref(),
            Some("64158303232")
        );
        assert_eq!(
            volume::plist_value(xml, "VolumeName").as_deref(),
            Some("ARCA")
        );
        assert_eq!(
            volume::plist_value(xml, "VolumeUUID").as_deref(),
            Some("1A2B3C4D-0000-1111-2222-333344445555")
        );
        assert_eq!(volume::plist_value(xml, "Nope"), None);
    }

    #[test]
    fn windows_volume_parsing_takes_an_array_or_a_single_object() {
        let one = r#"{"DriveLetter":"E","FileSystemLabel":"ARCA","Size":64158303232,"UniqueId":"\\\\?\\Volume{9d2c}\\"}"#;
        let vols = volume::parse_windows_volumes(one);
        assert_eq!(vols.len(), 1);
        assert_eq!(vols[0].label, "ARCA");
        assert_eq!(vols[0].root, Some(PathBuf::from("E:\\")));
        assert_eq!(vols[0].id, "\\\\?\\Volume{9d2c}\\");
        assert_eq!(vols[0].size, 64158303232);

        // Older PowerShell: DriveLetter as a char code, no label, no id.
        let many = r#"[{"DriveLetter":70,"FileSystemLabel":"","Size":1,"UniqueId":""},{"DriveLetter":null}]"#;
        let vols = volume::parse_windows_volumes(many);
        assert_eq!(vols.len(), 1);
        assert_eq!(vols[0].label, "F:");
        assert_eq!(vols[0].id, "F:\\");

        assert!(volume::parse_windows_volumes("").is_empty());
    }
}
