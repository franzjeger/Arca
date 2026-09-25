//! macOS device-key migration. Keychain prompts never hold the vault mutex.
//! The presence of the config file is sticky: missing/invalid protected keys
//! must never fall back to the legacy login-keychain key.
use crate::state::{AppState, CmdError};
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    sync::Mutex,
};
use vault_core::SymmetricKey;
use vault_sharedkey::protected;
use vault_store::VaultStore;

// One system prompt for the desktop process, shared by the window, browser
// bridge and enrollment. A duplicate must not cancel the current generation.
static AUTHENTICATION: Mutex<()> = Mutex::new(());
fn claim_authentication(gate: &Mutex<()>) -> Result<std::sync::MutexGuard<'_, ()>, CmdError> {
    gate.try_lock().map_err(|error| match error {
        std::sync::TryLockError::WouldBlock => CmdError::new(
            "unlock_in_progress",
            "Authentication is already in progress.",
        ),
        std::sync::TryLockError::Poisoned(_) => {
            failure("Authentication service unavailable. Restart Arca and try again.")
        }
    })
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
struct Config {
    account: Option<String>,
}
fn path(store: &VaultStore) -> PathBuf {
    store.path().with_file_name("quick-unlock.json")
}
fn load(store: &VaultStore) -> Result<Option<Config>, CmdError> {
    match std::fs::read(path(store)) {
        Ok(bytes) => {
            let config: Config = serde_json::from_slice(&bytes).map_err(|_| failure("Quick-unlock settings are unreadable. Unlock with your master password and repair Touch ID in Settings."))?;
            if let Some(account) = &config.account {
                let suffix = account
                    .strip_prefix("desktop-protected-")
                    .ok_or_else(|| failure("Invalid protected key account."))?;
                uuid::Uuid::parse_str(suffix)
                    .map_err(|_| failure("Invalid protected key account."))?;
            }
            Ok(Some(config))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(failure("Could not read quick-unlock settings.")),
    }
}
// An unlocked user may repair a malformed marker, but never interpret it as
// permission to use the legacy key. Preserve protected mode on rollback.
fn load_for_setup(store: &VaultStore) -> Result<Option<Config>, CmdError> {
    match load(store) {
        Err(_) if std::fs::read(path(store)).is_ok() => Ok(Some(Config { account: None })),
        result => result,
    }
}
fn write(store: &VaultStore, config: &Config) -> Result<(), CmdError> {
    let bytes = serde_json::to_vec(config)
        .map_err(|_| failure("Could not encode quick-unlock settings."))?;
    vault_store::write_atomic(&path(store), &bytes)
        .map_err(|_| failure("Could not save quick-unlock settings."))
}
fn failure(message: &str) -> CmdError {
    CmdError::new("quick_unlock_protection", message)
}
fn key_error(status: i32) -> CmdError {
    match status {
        -128 | -25293 => CmdError::new("biometric_failed", "Touch ID was cancelled or not confirmed."),
        -34018 => failure("This build lacks the signing profile needed for protected Touch ID. Your master password still works."),
        _ => failure("The protected key could not be read. Unlock with your master password and repair Touch ID in Settings."),
    }
}

pub fn uses_protected(store: &VaultStore) -> bool {
    !matches!(load(store), Ok(None))
}
pub fn available(store: &VaultStore) -> bool {
    match load(store) {
        Ok(Some(Config {
            account: Some(account),
        })) => protected::exists(&account).unwrap_or(false),
        Ok(Some(_)) | Err(_) => false,
        Ok(None) => store.quick_unlock_available(),
    }
}
pub fn fully_protected(store: &VaultStore) -> bool {
    uses_protected(store) && available(store) && !store.quick_unlock_available()
}

fn begin(
    state: &Mutex<AppState>,
    require_unlocked: bool,
) -> Result<(u64, PathBuf, Option<Config>), CmdError> {
    let mut st = state.lock().map_err(|_| failure("Vault unavailable."))?;
    if require_unlocked && !st.vault()?.is_unlocked() {
        return Err(CmdError::new("locked", "Unlock the vault first."));
    }
    let config = if require_unlocked {
        load_for_setup(&st.store)?
    } else {
        load(&st.store)?
    };
    if require_unlocked {
        st.blur_grace_until = Some(std::time::Instant::now() + std::time::Duration::from_secs(60));
    }
    st.unlock_generation = st.unlock_generation.wrapping_add(1);
    Ok((st.unlock_generation, st.store.path().to_owned(), config))
}
fn current(st: &AppState, generation: u64, vault_path: &Path) -> Result<(), CmdError> {
    if st.unlock_generation != generation || st.store.path() != vault_path {
        Err(CmdError::new(
            "unlock_cancelled",
            "The vault session changed during authentication. Try again.",
        ))
    } else {
        Ok(())
    }
}

/// Runs on a worker, including when invoked by the browser bridge.
pub fn unlock(state: &Mutex<AppState>, app: Option<&tauri::AppHandle>) -> Result<(), CmdError> {
    let _prompt = claim_authentication(&AUTHENTICATION)?;
    if state
        .lock()
        .map_err(|_| failure("Vault unavailable."))?
        .vault
        .as_ref()
        .is_some_and(|v| v.is_unlocked())
    {
        return Ok(());
    }
    let (generation, vault_path, config) = begin(state, false)?;
    let key = match &config {
        Some(Config {
            account: Some(account),
        }) => SymmetricKey::from_bytes(*protected::read(account).map_err(key_error)?),
        Some(_) => {
            return Err(failure(
                "Touch ID is disabled. Unlock with your master password.",
            ))
        }
        None => {
            crate::biometric::authenticate(app, "unlock your password vault")
                .map_err(|message| CmdError::new("biometric_failed", &message))?;
            let st = state.lock().map_err(|_| failure("Vault unavailable."))?;
            current(&st, generation, &vault_path)?;
            st.store
                .device_key()?
                .ok_or_else(|| failure("Quick unlock is not enabled."))?
        }
    };
    let mut st = state.lock().map_err(|_| failure("Vault unavailable."))?;
    current(&st, generation, &vault_path)?;
    if load(&st.store)? != config {
        return Err(failure("Quick-unlock settings changed. Try again."));
    }
    if st.vault.is_none() {
        st.vault = Some(st.store.load()?);
    }
    // Validate before retiring any legacy copy or changing live vault state.
    if !st.vault()?.device_key_matches(&key) {
        return Err(CmdError::new("quick_unlock_stale", "Quick unlock is out of sync. Unlock with your master password and repair Touch ID in Settings."));
    }
    if config.is_some() {
        st.store.clear_device_key()?;
    }
    st.vault_mut()?.unlock_with_device_key(&key)?;
    if config.is_none() {
        // Reuse the key already read for this unlock. Publishing identities
        // used to read it again, potentially causing a second system prompt.
        let shared = vault_sharedkey::store(key.as_bytes());
        if shared != vault_sharedkey::Mirrored::Ok {
            eprintln!("[arca] legacy AutoFill key: {shared}");
        }
    }
    st.touch();
    Ok(())
}

struct StagedKey {
    account: String,
    committed: bool,
}
impl Drop for StagedKey {
    fn drop(&mut self) {
        if !self.committed {
            let _ = protected::delete(&self.account);
        }
    }
}

/// Enable, upgrade or repair from an already unlocked vault. The old key is
/// retained until the protected replacement was authenticated and committed.
pub fn enable(state: &Mutex<AppState>) -> Result<(), CmdError> {
    let _prompt = claim_authentication(&AUTHENTICATION)?;
    let (generation, vault_path, previous) = begin(state, true)?;
    let key = {
        let st = state.lock().map_err(|_| failure("Vault unavailable."))?;
        current(&st, generation, &vault_path)?;
        // Reuse a valid legacy key for migration: no vault-format or header change.
        // A repair/new enrollment creates a new key and stages its header below.
        let legacy = if previous.is_none() {
            st.store.device_key()?
        } else {
            None
        };
        match legacy {
            Some(key) if st.vault()?.device_key_matches(&key) => key,
            _ => SymmetricKey::generate()?,
        }
    };
    let account = format!("desktop-protected-{}", uuid::Uuid::new_v4());
    protected::create(&account, key.as_bytes()).map_err(key_error)?;
    let mut staged = StagedKey {
        account,
        committed: false,
    };
    let verified = SymmetricKey::from_bytes(*protected::read(&staged.account).map_err(key_error)?);
    if key != verified {
        return Err(failure("Protected key verification failed."));
    }
    let mut st = state.lock().map_err(|_| failure("Vault unavailable."))?;
    current(&st, generation, &vault_path)?;
    if !st.vault()?.is_unlocked() || load_for_setup(&st.store)? != previous {
        return Err(failure("The vault session changed. Try again."));
    }
    let mut candidate = st.vault()?.clone();
    let header_changed = !candidate.device_key_matches(&verified);
    if header_changed {
        candidate.enable_device_unlock(&verified)?;
    }
    let next = Config {
        account: Some(staged.account.clone()),
    };
    if let Err((error, retain_key)) = commit_config(&st.store, &next, previous.as_ref(), || {
        if header_changed {
            st.store.save_synced(&mut candidate)?;
        }
        Ok(())
    }) {
        staged.committed = retain_key;
        return Err(error);
    }
    if header_changed {
        st.vault = Some(candidate);
        crate::sync::mark_dirty();
    }
    staged.committed = true;
    // The AutoFill copy is independently protected; copy the already verified
    // key now, without another keychain read or biometric prompt.
    let shared = vault_sharedkey::store(verified.as_bytes());
    if shared != vault_sharedkey::Mirrored::Ok {
        eprintln!("[arca] protected AutoFill key: {shared}");
    }
    st.store.clear_device_key().map_err(|_| failure("Protected Touch ID is active, but removing the old key failed. Retry Repair Touch ID in Settings."))?;
    if let Some(Config { account: Some(old) }) = previous {
        let _ = protected::delete(&old);
    }
    st.touch();
    Ok(())
}

/// Config is written first; save failure restores the previous pointer. The
/// bool on failure says whether the staged key might still be referenced.
fn commit_config(
    store: &VaultStore,
    next: &Config,
    previous: Option<&Config>,
    save: impl FnOnce() -> Result<(), CmdError>,
) -> Result<(), (CmdError, bool)> {
    write(store, next).map_err(|e| (e, false))?;
    if let Err(error) = save() {
        let rolled_back = match previous {
            Some(config) => write(store, config),
            None => std::fs::remove_file(path(store))
                .map_err(|_| failure("Could not restore previous quick-unlock settings.")),
        };
        return Err((error, rolled_back.is_err()));
    }
    Ok(())
}

/// Sticky protected mode survives disable and restore: never recreate a plain key.
pub fn clear(store: &VaultStore) -> Result<(), CmdError> {
    let previous = load_for_setup(store)?;
    if previous.is_some() {
        write(store, &Config { account: None })?;
        if let Some(Config {
            account: Some(account),
        }) = previous
        {
            protected::delete(&account).map_err(key_error)?;
        }
    }
    store.clear_device_key()?;
    let status = vault_sharedkey::clear();
    if let vault_sharedkey::Mirrored::Failed(code) = status {
        return Err(key_error(code));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn protected_mode_is_sticky_and_malformed_config_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let store = VaultStore::new(dir.path().join("vault"), "test", "test");
        assert!(!uses_protected(&store));
        write(&store, &Config { account: None }).unwrap();
        assert!(uses_protected(&store));
        assert!(!available(&store));
        std::fs::write(path(&store), b"broken").unwrap();
        assert!(uses_protected(&store));
        assert!(!available(&store));
        assert!(load(&store).is_err());
        assert_eq!(
            load_for_setup(&store).unwrap(),
            Some(Config { account: None })
        );
    }
    #[test]
    fn failed_vault_save_restores_the_old_key_reference() {
        let dir = tempfile::tempdir().unwrap();
        let store = VaultStore::new(dir.path().join("vault"), "test", "test");
        let old = Config {
            account: Some(format!("desktop-protected-{}", uuid::Uuid::new_v4())),
        };
        let next = Config {
            account: Some(format!("desktop-protected-{}", uuid::Uuid::new_v4())),
        };
        write(&store, &old).unwrap();
        let (_, retain) =
            commit_config(&store, &next, Some(&old), || Err(failure("Disk full"))).unwrap_err();
        assert!(!retain);
        assert_eq!(load(&store).unwrap(), Some(old));
        std::fs::remove_file(path(&store)).unwrap();
        assert!(commit_config(&store, &next, None, || Err(failure("Disk full"))).is_err());
        assert_eq!(load(&store).unwrap(), None);
    }

    #[test]
    fn failed_config_write_never_calls_the_vault_save() {
        let dir = tempfile::tempdir().unwrap();
        let store = VaultStore::new(dir.path().join("vault"), "test", "test");
        std::fs::create_dir(path(&store)).unwrap();
        let result = commit_config(&store, &Config { account: None }, None, || {
            panic!("must not save")
        });
        assert!(result.is_err());
    }

    #[test]
    fn failed_rollback_retains_the_staged_key() {
        let dir = tempfile::tempdir().unwrap();
        let store = VaultStore::new(dir.path().join("vault"), "test", "test");
        let (_, retain) = commit_config(&store, &Config { account: None }, None, || {
            std::fs::remove_file(path(&store)).unwrap();
            std::fs::create_dir(path(&store)).unwrap();
            Err(failure("Disk failed"))
        })
        .unwrap_err();
        assert!(retain);
    }

    #[test]
    fn lock_or_a_new_attempt_invalidates_a_pending_authentication() {
        let dir = tempfile::tempdir().unwrap();
        let store = VaultStore::new(dir.path().join("vault"), "test", "test");
        let (clipboard, _) = crate::clipboard::ClipboardManager::memory();
        let state = Mutex::new(AppState::new(store, None, clipboard));
        let (first, path, _) = begin(&state, false).unwrap();
        assert!(current(&state.lock().unwrap(), first, &path).is_ok());
        let (second, _, _) = begin(&state, false).unwrap();
        assert!(current(&state.lock().unwrap(), first, &path).is_err());
        state.lock().unwrap().unlock_generation += 1;
        assert!(current(&state.lock().unwrap(), second, &path).is_err());
    }
    #[test]
    fn overlapping_requests_cannot_start_a_second_prompt_but_retry_is_allowed() {
        let gate = Mutex::new(());
        let first = claim_authentication(&gate).unwrap();
        assert_eq!(
            claim_authentication(&gate).unwrap_err().code,
            "unlock_in_progress"
        );
        drop(first); // success, cancellation and errors all release the guard
        assert!(claim_authentication(&gate).is_ok());
    }
    #[test]
    fn an_already_open_vault_needs_no_second_authentication() {
        let dir = tempfile::tempdir().unwrap();
        let store = VaultStore::new(dir.path().join("vault"), "test", "test");
        // No active key: reaching the authentication path would fail.
        write(&store, &Config { account: None }).unwrap();
        let mut params = vault_core::KdfParams::new_default().unwrap();
        params.m_cost_kib = 256;
        params.t_cost = 1;
        let vault = vault_core::Vault::create("test", params).unwrap();
        let (clipboard, _) = crate::clipboard::ClipboardManager::memory();
        let state = Mutex::new(AppState::new(store, Some(vault), clipboard));
        assert!(unlock(&state, None).is_ok());
        assert_eq!(state.lock().unwrap().unlock_generation, 0);
    }
}
