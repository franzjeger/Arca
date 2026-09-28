//! End-to-end encrypted vault sync, independent of any UI or platform.
//!
//! This was ~670 lines inside the Tauri desktop crate, which meant nothing else
//! could call it — and "nothing else" included the iOS app, for which it is the
//! difference between a real password manager and a viewer you hand-feed a file
//! (see `docs/IOS.md`). Moving it out is what makes a second client possible.
//!
//! The security model is unchanged and worth restating: the remote holds
//! **ciphertext only**. The vault is sealed with Argon2id + XChaCha20-Poly1305
//! before it leaves the machine, so the storage provider is transport and never
//! trust. Nothing in this crate can decrypt anything.
//!
//! ## What is abstracted, and why
//!
//! Three traits, each standing where a platform difference actually is:
//!
//! * [`RemoteStore`] — the remote side. [`drive::DriveStore`] is Google Drive's
//!   `appDataFolder`; the fake in this crate's tests is the other implementation,
//!   and it is what finally makes the cycle's decisions testable. That logic
//!   guards against clobbering a peer's changes and had no tests at all while it
//!   lived in the app.
//! * [`LocalVault`] — the local side. The engine never sees a `Vault`; it asks
//!   for "merge these copies and give me the bytes to push". The merge *policy*
//!   is [`merge_remotes`] so every platform applies the same one.
//! * [`SyncObserver`] — progress. The desktop turns these into Tauri events; a
//!   phone would drive an observable property.
//!
//! Authentication is deliberately NOT a trait. Refreshing a token is an HTTP
//! POST and lives in [`oauth`]; obtaining one the first time is a loopback
//! listener on desktop and `ASWebAuthenticationSession` on iOS, with nothing
//! useful in common, so each caller runs its own and hands over the result.
//!
//! ## The engine's invariants
//!
//! Carried over verbatim from the desktop implementation, which had been through
//! adversarial review; the tests here are the first mechanical check of them:
//!
//! * one cycle at a time, across the background loop and any manual trigger;
//! * upload only when something actually changed — local edits, a merge, or a
//!   bootstrap — so an idle app does not rewrite the remote every 30 seconds;
//! * the remote checksum is recorded **only from our own upload response**,
//!   never from a listing, so a peer's concurrent upload can never be mistaken
//!   for content we already integrated;
//! * a cheap checksum preflight before pushing; if the remote moved under us the
//!   whole cycle re-runs rather than overwriting what we have not merged;
//! * every push creates an immutable remote file; only inputs already merged
//!   into that successful upload are deleted, so concurrent pushes survive;
//! * a remote written by a NEWER format is refused, never "repaired";
//! * a remote sealed after a master password change this device has not taken
//!   on stops the cycle until the user enters the new password, and one sealed
//!   before a change is replaced, never merged.

#![forbid(unsafe_code)]

pub mod drive;
pub mod engine;
mod http;
pub mod oauth;

use std::fmt;

use vault_core::Vault;

pub use engine::{SyncEngine, SyncStatus};

/// A remote vault copy: its id and the checksum the remote reports for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteFile {
    pub id: String,
    pub checksum: String,
}

/// How a cycle failed, classified because the classification drives the retry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CycleError {
    /// A peer wrote the remote mid-cycle. Re-run pull→merge→push; do not push.
    Conflict,
    /// The credential was rejected. Refresh once, then give up.
    Auth,
    /// Everything else, already phrased for a person.
    Other(String),
}

impl fmt::Display for CycleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CycleError::Conflict => write!(f, "another device wrote the vault mid-sync"),
            CycleError::Auth => write!(f, "the sign-in was rejected"),
            CycleError::Other(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for CycleError {}

impl From<String> for CycleError {
    fn from(s: String) -> Self {
        CycleError::Other(s)
    }
}

/// Why the local vault could not produce bytes to push.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalError {
    /// The vault is shut. Not an error: the cycle backs off and retries, having
    /// re-flagged any local changes rather than dropping them.
    Locked,
    /// The remote was written by a newer version of the app. Refused on purpose
    /// — merging a format we do not understand is how a vault gets corrupted.
    RemoteTooNew,
    /// A remote copy was sealed after a master password change this device
    /// has not taken on. Carries the newest such copy, which the engine keeps
    /// for `Vault::adopt_rotation` (see [`SyncEngine::rotated_copy`]).
    KeyRotated(Vec<u8>),
    /// A foreign vault (different key), or any other refusal from the core.
    Refused(String),
    /// The merged result could not be persisted locally.
    Save(String),
}

impl fmt::Display for LocalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LocalError::Locked => write!(f, "the vault is locked"),
            LocalError::RemoteTooNew => write!(
                f,
                "the synced vault was written by a newer Arca — update this app"
            ),
            LocalError::KeyRotated(_) => write!(
                f,
                "the master password was changed on another device — enter the new one to keep syncing"
            ),
            LocalError::Refused(m) => write!(f, "remote vault refused: {m}"),
            LocalError::Save(m) => write!(f, "could not save locally: {m}"),
        }
    }
}

impl std::error::Error for LocalError {}

/// The remote side of sync.
///
/// Implementations must be safe to call from the sync thread and must not
/// prompt the user — [`is_connected`](RemoteStore::is_connected) especially,
/// which runs every tick.
pub trait RemoteStore: Send + Sync {
    /// Whether a credential exists at all. Must be cheap and must never read
    /// the credential's *data*: on macOS that runs the keychain item's ACL and
    /// can put a prompt on screen.
    fn is_connected(&self) -> bool;

    /// Every remote vault copy, **oldest first**. Normally zero or one; more
    /// only after two devices raced to create it.
    ///
    /// An error here must be surfaced, never flattened to "no file" — that is
    /// exactly how duplicate creation happens.
    fn list(&self) -> Result<Vec<RemoteFile>, CycleError>;

    fn download(&self, id: &str) -> Result<Vec<u8>, CycleError>;

    /// The remote's current checksum for a file — the cheap preflight that
    /// catches a peer writing between our download and our upload.
    fn checksum(&self, id: &str) -> Result<String, CycleError>;

    fn delete(&self, id: &str) -> Result<(), CycleError>;

    /// Create or replace, returning the id and checksum **from the response**.
    /// The engine always creates (`existing = None`): published files are
    /// immutable, so concurrent uploads cannot overwrite each other.
    /// The engine records that checksum as integrated, so it has to describe
    /// what was actually written rather than what we hoped to write.
    fn upload(&self, existing: Option<&str>, bytes: &[u8]) -> Result<RemoteFile, CycleError>;

    /// Drop any cached credential after [`CycleError::Auth`], so the next call
    /// acquires a fresh one.
    fn invalidate_auth(&self) {}
}

/// The local side of sync.
///
/// The engine never sees a `Vault`. It hands over the remote copies it pulled
/// and receives the bytes to push, which keeps every question of how the vault
/// is stored, locked, or persisted on the caller's side of the line.
pub trait LocalVault: Send + Sync {
    /// Merge `remotes` into the local vault, persist the result, and return the
    /// bytes to upload. Implementations should apply the shared policy by
    /// calling [`merge_remotes`].
    fn merge_and_serialize(&self, remotes: &[Vec<u8>]) -> Result<Vec<u8>, LocalError>;
}

/// Sync progress, for whatever the platform shows a user.
pub trait SyncObserver: Send + Sync {
    /// Remote changes were merged into the local vault — the UI should reload.
    fn merged(&self) {}
    /// The status changed (a sync finished, or failed).
    fn status_changed(&self, _status: &SyncStatus) {}
}

/// A [`SyncObserver`] that does nothing, for callers with no UI.
pub struct SilentObserver;
impl SyncObserver for SilentObserver {}

/// The merge policy, shared so every platform treats a bad remote the same way.
///
/// The classification is the interesting part:
///
/// * a torn upload (`Format`) is **skipped**, and ours replaces it — half a
///   file, with nothing in it authenticated, is not content worth preserving;
/// * so is a copy sealed before a master password change (`StaleKey`): anyone
///   who knew the old password could have written it, and the device that did
///   brings its edits back once it has the new password;
/// * a copy sealed after a change this device has not taken on stops the
///   cycle with the newest such copy ([`LocalError::KeyRotated`]), once the
///   copies we can open have merged;
/// * a newer format is **refused**, because merging a schema we do not
///   understand is how a vault loses items. That includes an authentic file
///   whose items this build cannot decode;
/// * anything else — a foreign vault sealed with a different key above all — is
///   refused too. Overwriting it would destroy someone's data.
pub fn merge_remotes(vault: &mut Vault, remotes: &[Vec<u8>]) -> Result<(), LocalError> {
    let mut rotated = false;
    for bytes in remotes {
        match vault.merge_remote(bytes) {
            Ok(()) => {}
            Err(vault_core::Error::Format | vault_core::Error::StaleKey) => {}
            Err(vault_core::Error::KeyRotated) => rotated = true,
            Err(vault_core::Error::UnsupportedVersion) => return Err(LocalError::RemoteTooNew),
            Err(e) => return Err(LocalError::Refused(e.to_string())),
        }
    }
    match newest_rotation(vault, remotes) {
        Some(copy) if rotated => Err(LocalError::KeyRotated(copy)),
        _ => Ok(()),
    }
}

/// What a platform's [`LocalVault`] reports while its vault is locked:
/// [`LocalError::KeyRotated`] when a remote copy comes from a master password
/// change this vault has not taken on, so the lock screen can ask for the new
/// password, and [`LocalError::Locked`] otherwise.
pub fn locked(vault: &Vault, remotes: &[Vec<u8>]) -> LocalError {
    newest_rotation(vault, remotes).map_or(LocalError::Locked, LocalError::KeyRotated)
}

/// The remote copy from the latest password change `vault` has not taken on.
/// Only the latest matters: its password is the one the user knows, and it
/// carries the keys of every change before it.
fn newest_rotation(vault: &Vault, remotes: &[Vec<u8>]) -> Option<Vec<u8>> {
    let ours = vault.header().key_epoch;
    remotes
        .iter()
        .filter_map(|bytes| Some((Vault::from_bytes(bytes).ok()?.header().key_epoch, bytes)))
        .filter(|(epoch, _)| *epoch > ours)
        .max_by_key(|(epoch, _)| *epoch)
        .map(|(_, bytes)| bytes.clone())
}

#[cfg(test)]
mod merge_remotes_tests {
    use super::*;
    use vault_core::header::{KdfAlgorithm, KdfParams};

    fn cheap_vault() -> Vault {
        // A deliberately weak KDF: these tests are about how a remote is
        // classified, not about how long Argon2id takes.
        Vault::create(
            "pw",
            KdfParams {
                algorithm: KdfAlgorithm::Argon2id,
                m_cost_kib: 256,
                t_cost: 1,
                p_cost: 1,
                salt: vec![7u8; KdfParams::SALT_LEN],
            },
        )
        .unwrap()
    }

    /// The distinction that protects the user's data. `Format` means "replace
    /// it with ours", so a vault written by a newer Arca landing in that arm
    /// would be overwritten and everything it holds lost.
    #[test]
    fn a_newer_container_is_refused_while_a_torn_one_is_skipped() {
        let mut vault = cheap_vault();

        let mut newer = b"SYBRVLT9".to_vec();
        newer.extend_from_slice(&[0u8; 64]);
        assert!(matches!(
            merge_remotes(&mut vault, &[newer]),
            Err(LocalError::RemoteTooNew)
        ));

        // Half an upload is not content worth keeping, and refusing it would
        // wedge every future sync behind one bad file — our own container
        // cut short included, which used to be refused forever.
        assert!(merge_remotes(&mut vault, &[b"garbage".to_vec()]).is_ok());
        let ours = vault.to_bytes().unwrap();
        assert!(merge_remotes(&mut vault, &[ours[..ours.len() - 10].to_vec()]).is_ok());
    }

    /// After a password change elsewhere, the copies we can open still merge,
    /// the cycle asks for the password with the newest changed copy, and a
    /// copy from before the change is dropped rather than merged or refused.
    #[test]
    fn a_password_change_elsewhere_asks_for_the_newest_copy() {
        let mut here = cheap_vault();
        let base = here.to_bytes().unwrap();
        let mut there = Vault::from_bytes(&base).unwrap();
        there.unlock("pw").unwrap();
        there.change_master_password("new").unwrap();
        let rotated = there.to_bytes().unwrap();

        let shut = Vault::from_bytes(&base).unwrap();
        assert_eq!(
            locked(&shut, &[base.clone(), rotated.clone()]),
            LocalError::KeyRotated(rotated.clone())
        );
        assert_eq!(
            locked(&shut, std::slice::from_ref(&base)),
            LocalError::Locked
        );

        assert_eq!(
            merge_remotes(&mut here, &[rotated.clone(), base.clone()]),
            Err(LocalError::KeyRotated(rotated.clone()))
        );
        here.adopt_rotation(&rotated, "new").unwrap();
        assert_eq!(merge_remotes(&mut here, &[base, rotated]), Ok(()));
    }
}
