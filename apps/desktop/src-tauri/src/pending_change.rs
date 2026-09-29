//! A master password change made on another device that this computer has not
//! taken on yet.
//!
//! Sync finds the change as a copy of the vault sealed with a key this
//! computer lacks. That copy used to live only in the sync engine's memory,
//! where a restart or a lock lost it, and it only raised a question: the old
//! password and quick unlock went on opening the vault here. It is now kept
//! beside the vault, and while it is there this computer opens with the new
//! password only, which takes the change on (`rotation::adopt`). Quick unlock
//! wrapped the key the change replaced, so it goes the moment the change is
//! known; taking the change on brings it back as before.
//!
//! Such a copy is not proof. The key that could prove it is the one this
//! computer lacks, and whoever can write to the Google account can put a copy
//! there. So the user can say they did not change the password: the previous
//! password and this computer's own verification (Touch ID, Windows Hello)
//! open the vault as before, and that copy is set aside for good (`deny`).

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use vault_core::Vault;
use vault_store::VaultStore;

use crate::state::AppState;

/// Beside the vault, never synced.
const PENDING: &str = "pending-password-change.vault";
/// The copy the user said was not their change, by its SHA-256.
const DENIED: &str = "denied-password-change";

fn pending_path(store: &VaultStore) -> PathBuf {
    store.path().with_file_name(PENDING)
}

fn denied_path(store: &VaultStore) -> PathBuf {
    store.path().with_file_name(DENIED)
}

fn fingerprint(copy: &[u8]) -> String {
    Sha256::digest(copy)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn epoch_of(copy: &[u8]) -> Option<u64> {
    Vault::from_bytes(copy).ok().map(|v| v.header().key_epoch)
}

/// The key epoch of the vault this computer holds, open or not.
fn local_epoch(st: &AppState) -> Option<u64> {
    match &st.vault {
        Some(vault) => Some(vault.header().key_epoch),
        None => st.store.load().ok().map(|v| v.header().key_epoch),
    }
}

fn denied(store: &VaultStore, copy: &[u8]) -> bool {
    is_denied_at(store.path(), copy)
}

/// Whether `copy` is the one the user said was not their change, given the
/// vault file's path. For sync's status, which cannot take the app state's lock.
pub fn is_denied_at(vault_path: &Path, copy: &[u8]) -> bool {
    std::fs::read_to_string(vault_path.with_file_name(DENIED))
        .is_ok_and(|d| d.trim() == fingerprint(copy))
}

/// Sync found `copy`, sealed after a password change this vault has not taken
/// on. Keep it, unless it is one the user said was not their change. Returns
/// whether it was kept now, which is when quick unlock has to go
/// ([`drop_quick_unlock`]).
pub fn record(st: &AppState, copy: &[u8]) -> bool {
    let (Some(theirs), Some(ours)) = (epoch_of(copy), local_epoch(st)) else {
        return false;
    };
    if theirs <= ours || denied(&st.store, copy) {
        return false;
    }
    // The same copy again is nothing new, and an earlier change never
    // replaces a later one.
    if let Some(kept) = pending(st) {
        if kept == copy || epoch_of(&kept).is_some_and(|kept| kept > theirs) {
            return false;
        }
    }
    vault_store::write_atomic(&pending_path(&st.store), copy).is_ok()
}

/// Remove quick unlock, which wrapped the key the change replaced: Touch ID and
/// the AutoFill extension's copy of its key on macOS, the keychain device key
/// elsewhere. The keys only. The vault's header still says quick unlock was
/// on, which is how taking the change on, or denying it, knows to bring it back.
pub fn drop_quick_unlock(store: &VaultStore) {
    #[cfg(target_os = "macos")]
    let _ = crate::protected_unlock::clear(store);
    #[cfg(not(target_os = "macos"))]
    let _ = store.clear_device_key();
}

/// The kept copy while it is still ahead of this vault. One the vault has
/// caught up with, or that no longer reads as a vault, is removed.
pub fn pending(st: &AppState) -> Option<Vec<u8>> {
    let path = pending_path(&st.store);
    let copy = std::fs::read(&path).ok()?;
    match (epoch_of(&copy), local_epoch(st)) {
        (Some(theirs), Some(ours)) if theirs > ours => Some(copy),
        _ => {
            let _ = std::fs::remove_file(&path);
            None
        }
    }
}

/// The change was taken on.
pub fn clear(store: &VaultStore) {
    let _ = std::fs::remove_file(pending_path(store));
}

/// The user says they did not make this change: set the kept copy aside for
/// good, so the same copy is never kept again.
pub fn deny(st: &AppState) -> std::io::Result<()> {
    if let Some(copy) = pending(st) {
        vault_store::write_atomic(&denied_path(&st.store), fingerprint(&copy).as_bytes())?;
    }
    clear(&st.store);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_core::KdfParams;

    fn cheap() -> KdfParams {
        let mut params = KdfParams::new_default().unwrap();
        params.m_cost_kib = 256;
        params.t_cost = 1;
        params
    }

    /// A vault saved here, and a copy of it after a password change made
    /// elsewhere.
    fn here_and_changed(dir: &std::path::Path) -> (AppState, Vec<u8>) {
        let store = VaultStore::new(dir.join("vault"), "test", "pending");
        let vault = Vault::create("old", cheap()).unwrap();
        store.save(&vault).unwrap();
        let mut elsewhere = Vault::from_bytes(&vault.to_bytes().unwrap()).unwrap();
        elsewhere.unlock("old").unwrap();
        elsewhere.change_master_password("new").unwrap();
        let changed = elsewhere.to_bytes().unwrap();
        let (clipboard, _) = crate::clipboard::ClipboardManager::memory();
        (AppState::new(store, None, clipboard), changed)
    }

    #[test]
    fn a_change_is_kept_until_the_vault_catches_up() {
        let dir = tempfile::tempdir().unwrap();
        let (mut st, changed) = here_and_changed(dir.path());
        assert!(pending(&st).is_none());
        assert!(record(&st, &changed));
        assert!(!record(&st, &changed), "the same copy again is nothing new");
        assert_eq!(pending(&st).as_deref(), Some(changed.as_slice()));

        // The vault took the change on another way: nothing is pending.
        let mut vault = st.store.load().unwrap();
        vault.adopt_rotation(&changed, "new").unwrap();
        st.store.save(&vault).unwrap();
        st.vault = Some(vault);
        assert!(pending(&st).is_none());
        assert!(!pending_path(&st.store).exists());
    }

    #[test]
    fn a_denied_copy_is_never_kept_again() {
        let dir = tempfile::tempdir().unwrap();
        let (st, changed) = here_and_changed(dir.path());
        record(&st, &changed);
        deny(&st).unwrap();
        assert!(pending(&st).is_none());
        assert!(is_denied_at(st.store.path(), &changed));
        assert!(!record(&st, &changed));
        assert!(pending(&st).is_none());
    }

    #[test]
    fn a_copy_that_is_not_ahead_is_not_a_change() {
        let dir = tempfile::tempdir().unwrap();
        let (st, _) = here_and_changed(dir.path());
        let same = st.store.load().unwrap().to_bytes().unwrap();
        assert!(!record(&st, &same));
        assert!(!record(&st, b"not a vault"));
        assert!(pending(&st).is_none());
    }
}
