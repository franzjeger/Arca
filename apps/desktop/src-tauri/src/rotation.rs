//! Master password changes: made here, or taken on from another device.
//!
//! Every change gives the vault a new key (`Vault::change_master_password`),
//! and whatever wrapped the old key stops opening the vault: the quick-unlock
//! slot, the USB key's sidecar, macOS's protected Touch ID key. This is where
//! they come back, so that a password change costs the user the password and
//! nothing else.

use std::sync::Mutex;

use serde::Serialize;
use tauri::AppHandle;

use crate::commands::{persist, write_guard};
use crate::state::{AppState, CmdError};

/// What a password change left for the window to say.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Rekeyed {
    /// Quick unlock was on and is off now: the Touch ID prompt that brings it
    /// back on macOS was declined. Settings turns it back on.
    pub quick_unlock_lost: bool,
}

/// Under the state lock, right after the key changed and before it is saved:
/// re-mint quick unlock where that takes no prompt (Windows, Linux), and
/// re-bind the USB key if it is plugged in (otherwise its next use asks for
/// the password once, as for any stale key). Returns whether macOS Touch ID
/// is still to come back, which prompts: see [`finish`].
pub fn restore_silently(st: &mut AppState, had_quick_unlock: bool) -> bool {
    if had_quick_unlock && !cfg!(target_os = "macos") {
        let AppState { store, vault, .. } = st;
        if let Some(vault) = vault.as_mut() {
            let _ = store.enable_quick_unlock(vault);
        }
    }
    crate::keyfile_unlock::heal(st);
    had_quick_unlock && cfg!(target_os = "macos")
}

/// After the change is saved and the state lock released: on macOS, one
/// Touch ID prompt for a protected key that wraps the new vault key.
pub async fn finish(app: &AppHandle, touch_id: bool) -> Rekeyed {
    if !touch_id {
        return Rekeyed {
            quick_unlock_lost: false,
        };
    }
    let worker = app.clone();
    let restored = tauri::async_runtime::spawn_blocking(move || restore_touch_id(&worker))
        .await
        .unwrap_or(false);
    Rekeyed {
        quick_unlock_lost: !restored,
    }
}

#[cfg(target_os = "macos")]
fn restore_touch_id(app: &AppHandle) -> bool {
    use tauri::Manager;
    let state = app.state::<Mutex<AppState>>();
    let restored = crate::protected_unlock::enable(state.inner()).is_ok();
    if restored {
        crate::commands::publish_identities(app);
    }
    restored
}

#[cfg(not(target_os = "macos"))]
fn restore_touch_id(_app: &AppHandle) -> bool {
    true
}

/// Take on a password change made on another device: `copy` is the one sync
/// keeps (`sync::rotated_copy`), `password` its new password. Works on a
/// locked vault too, and leaves it open. Returns whether Touch ID is still to
/// come back (see [`finish`]).
pub fn adopt(state: &Mutex<AppState>, copy: &[u8], password: &str) -> Result<bool, CmdError> {
    let mut st = write_guard(state)?;
    if st.vault.is_none() && st.store.exists() {
        st.vault = Some(st.store.load()?);
    }
    let vault = st.vault_mut()?;
    let was_locked = !vault.is_unlocked();
    let had_quick_unlock = vault.has_device_unlock();
    vault.adopt_rotation(copy, password).map_err(|e| match e {
        // Stashed before this vault caught up another way: nothing left
        // to take on, so the password was simply not this vault's.
        vault_core::Error::StaleKey => vault_core::Error::Decryption.into(),
        e => CmdError::from(e),
    })?;
    let touch_id = restore_silently(&mut st, had_quick_unlock);
    persist(&mut st)?;
    if was_locked {
        st.unlock_generation = st.unlock_generation.wrapping_add(1);
    }
    st.touch();
    drop(st);
    crate::sync::rotation_adopted();
    Ok(touch_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_core::{KdfParams, Vault};
    use vault_store::VaultStore;

    /// The laptop's password changed while this desktop sat locked. The new
    /// password alone opens it, and the vault it saves is the changed one.
    #[test]
    fn a_locked_vault_opens_with_a_password_set_on_another_device() {
        let dir = tempfile::tempdir().unwrap();
        let store = VaultStore::new(dir.path().join("vault"), "test", "rotation");
        let mut params = KdfParams::new_default().unwrap();
        params.m_cost_kib = 256;
        params.t_cost = 1;
        let here = Vault::create("old", params).unwrap();
        store.save(&here).unwrap();
        let mut laptop = here.clone();
        laptop.change_master_password("new").unwrap();
        let copy = laptop.to_bytes().unwrap();

        let locked = store.load().unwrap();
        let (clipboard, _) = crate::clipboard::ClipboardManager::memory();
        let state = Mutex::new(AppState::new(store, Some(locked), clipboard));
        let wrong = adopt(&state, &copy, "old").unwrap_err();
        assert_eq!(wrong.code, "invalid_credentials");
        assert!(!state.lock().unwrap().vault().unwrap().is_unlocked());

        assert!(
            !adopt(&state, &copy, "new").unwrap(),
            "no quick unlock to restore"
        );
        let st = state.lock().unwrap();
        assert!(st.vault().unwrap().is_unlocked());
        assert_eq!(st.vault().unwrap().header().key_epoch, 1);
        let mut saved = st.store.load().unwrap();
        assert!(saved.unlock("old").is_err());
        saved.unlock("new").unwrap();
    }
}
