//! # vault-store
//!
//! Persistence and OS-keychain quick-unlock for the SYBR password manager.
//!
//! * **One encrypted file**, written atomically (temp file in the same
//!   directory + `fsync` + `rename`), so a crash mid-write can never corrupt
//!   the vault — you keep either the old or the new bytes, never a torn mix.
//!   A non-secret sibling `.lock` file serializes independent local writers.
//! * **Quick/biometric unlock** via a device key kept in the OS keychain. The
//!   master password is never persisted (see [`keychain`]).
//!
//! All ciphertext/serialization lives in `vault-core`; this crate only moves
//! opaque bytes and talks to the OS.

mod error;
mod keychain;
pub mod secrets;
pub mod snapshot;

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

pub use error::{Error, Result};
use vault_core::SymmetricKey;
pub use vault_core::Vault;

/// Read a vault-shaped file without allowing a changed or malicious path to
/// allocate an unbounded buffer. The metadata check rejects normal oversize
/// files before allocation; `take` also closes the grow-after-stat race.
pub(crate) fn read_vault_file(path: &Path) -> Result<Vec<u8>> {
    let file = File::open(path)?;
    let len = file.metadata()?.len();
    if len > vault_core::MAX_VAULT_BYTES as u64 {
        return Err(vault_core::Error::Format.into());
    }
    let mut bytes = Vec::with_capacity(len as usize);
    file.take(vault_core::MAX_VAULT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > vault_core::MAX_VAULT_BYTES {
        return Err(vault_core::Error::Format.into());
    }
    Ok(bytes)
}

/// Deterministic 64-bit fingerprint of the on-disk bytes derived from SHA-256,
/// to detect that a synced peer or external process rewrote the file since we
/// last read/wrote it.
fn fingerprint(bytes: &[u8]) -> u64 {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(bytes);
    let mut arr = [0u8; 8];
    arr.copy_from_slice(&hash[..8]);
    u64::from_le_bytes(arr)
}

/// A vault on disk plus its OS-keychain quick-unlock binding.
pub struct VaultStore {
    path: PathBuf,
    keychain_service: String,
    keychain_account: String,
    /// Fingerprint of the bytes we last read/wrote, for external-change (sync)
    /// detection in [`VaultStore::save_synced`].
    last_seen: AtomicU64,
    /// A second path every successful write is copied to (see
    /// [`VaultStore::with_mirror`]).
    mirror: Option<PathBuf>,
}

impl VaultStore {
    /// Create a store for the vault at `path`. `keychain_service`/`account`
    /// namespace the device key in the OS secret store (e.g.
    /// `"no.sybr.vault"` / `"default-vault"`).
    pub fn new(
        path: impl Into<PathBuf>,
        keychain_service: impl Into<String>,
        keychain_account: impl Into<String>,
    ) -> Self {
        Self {
            path: path.into(),
            keychain_service: keychain_service.into(),
            keychain_account: keychain_account.into(),
            last_seen: AtomicU64::new(0),
            mirror: None,
        }
    }

    /// Copy every successful write to `path` as well.
    ///
    /// This exists for the macOS AutoFill extension, which is sandboxed to the
    /// App Group container and so cannot read the canonical vault in app data.
    /// It is deliberately here rather than at the call sites: there are five
    /// places that save a vault (commands, cloud sync, and three in the browser
    /// bridge), and a copy bolted onto some of them is a copy that goes stale
    /// the day someone adds a sixth. Exactly that happened — a sync-merged save
    /// left AutoFill serving the pre-merge vault.
    ///
    /// The mirror is a plain byte copy of an already-encrypted file, and it is
    /// best-effort: a failure to write it never fails the save.
    pub fn with_mirror(mut self, path: impl Into<PathBuf>) -> Self {
        self.mirror = Some(path.into());
        self
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// A stable sibling file is locked instead of the vault itself: atomic
    /// saves replace the vault inode with `rename`, which would otherwise leave
    /// a lock attached to the old inode while another process opens the new
    /// one. All Arca writers use this path, on Unix and Windows.
    fn open_write_lock(&self) -> Result<File> {
        let dir = self
            .path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(dir)?;
        let name = self
            .path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("vault");
        let lock_path = dir.join(format!("{name}.lock"));
        let mut opts = OpenOptions::new();
        opts.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        Ok(opts.open(lock_path)?)
    }

    fn acquire_write_lock(&self) -> Result<File> {
        let file = self.open_write_lock()?;
        fs2::FileExt::lock_exclusive(&file)?;
        Ok(file)
    }

    /// The one place vault bytes reach the disk. Both save paths route here so
    /// the mirror and the change-detection fingerprint cannot diverge from what
    /// was actually written.
    fn write_and_mirror(&self, bytes: &[u8]) -> Result<()> {
        write_atomic(&self.path, bytes)?;
        self.last_seen.store(fingerprint(bytes), Ordering::Relaxed);
        if let Some(mirror) = &self.mirror {
            // Written directly rather than copied from `self.path`: on macOS
            // `fs::copy` carries the source's mtime across, which made a fresh
            // mirror look twelve minutes stale and cost a round of doubt about
            // whether it had run at all.
            let _ = write_atomic(mirror, bytes);
        }
        Ok(())
    }

    /// Bring the mirror up to date with the file on disk, without saving.
    ///
    /// Saves keep the mirror current, but a session that only reads never
    /// saves — so after an unlock the mirror could still be whatever it was
    /// when the app last wrote, which on a machine that syncs from a phone is
    /// not the same vault at all. Returns false when there is no mirror or the
    /// copy failed; callers treat that as "AutoFill may be stale", never as a
    /// reason to fail.
    pub fn refresh_mirror(&self) -> bool {
        let Some(mirror) = &self.mirror else {
            return false;
        };
        match read_vault_file(&self.path) {
            Ok(bytes) => write_atomic(mirror, &bytes).is_ok(),
            Err(_) => false,
        }
    }

    /// Whether a vault file exists at the configured path.
    pub fn exists(&self) -> bool {
        self.path.is_file()
    }

    /// Load the (locked) vault from disk.
    pub fn load(&self) -> Result<Vault> {
        let bytes = read_vault_file(&self.path)?;
        self.last_seen.store(fingerprint(&bytes), Ordering::Relaxed);
        Ok(Vault::from_bytes(&bytes)?)
    }

    /// Serialize and atomically persist the vault.
    ///
    /// Snapshots the previous contents first (see [`snapshot`]), so a bad edit,
    /// bulk delete or merge can be rolled back. Snapshotting is best-effort: it
    /// must never be the reason a save fails.
    pub fn save(&self, vault: &Vault) -> Result<()> {
        let _write_lock = self.acquire_write_lock()?;
        let bytes = vault.to_bytes()?;
        let _ = snapshot::capture(&self.path);
        self.write_and_mirror(&bytes)
    }

    /// Export an atomic ciphertext copy and verify it can be read back intact.
    pub fn export_backup(&self, destination: &Path) -> Result<u64> {
        export_backup_file(&self.path, destination)
    }

    /// Snapshots of this vault, newest first (see [`snapshot::list`]).
    pub fn snapshots(&self) -> Vec<snapshot::SnapshotInfo> {
        snapshot::list(&self.path)
    }

    /// Roll the vault file back to `snapshot`, capturing the current state first
    /// so the restore itself is undoable. The caller must reload the vault from
    /// disk afterwards — the in-memory copy is now stale.
    pub fn restore_snapshot(&self, snapshot_path: &Path) -> Result<()> {
        let _write_lock = self.acquire_write_lock()?;
        snapshot::restore(&self.path, snapshot_path)?;
        // Force the next `save_synced` to re-read: the file changed under us.
        self.last_seen.store(0, Ordering::Relaxed);
        Ok(())
    }

    /// Take a snapshot right now, e.g. before a risky bulk operation (import,
    /// dedupe). Best-effort; returns the snapshot when one was written.
    pub fn snapshot_now(&self) -> Option<snapshot::SnapshotInfo> {
        snapshot::capture(&self.path).ok().flatten()
    }

    /// Sync-aware save: if the file on disk changed since we last read/wrote it
    /// (a synced peer rewrote it), merge those changes into `vault` first so the
    /// peer's edits aren't clobbered, then persist the merged result. Returns
    /// `true` if a merge happened. A foreign/corrupt external file surfaces as
    /// an error (the peer's file is *not* overwritten).
    pub fn save_synced(&self, vault: &mut Vault) -> Result<bool> {
        // Covers the complete read → merge → snapshot → atomic rename window.
        // Locking only the final write still lets two processes both merge the
        // same old file and then overwrite each other in succession.
        let _write_lock = self.acquire_write_lock()?;
        let mut merged = false;
        if self.path.is_file() {
            let current = read_vault_file(&self.path)?;
            if fingerprint(&current) != self.last_seen.load(Ordering::Relaxed) {
                match vault.merge_remote(&current) {
                    Ok(()) => merged = true,
                    // Unparseable bytes — a corrupt file, or a cloud daemon's
                    // in-progress partial write. It isn't a real vault, so
                    // replacing it with ours is safe and, crucially, doesn't
                    // wedge every future save behind a transient bad file.
                    Err(vault_core::Error::Format) | Err(vault_core::Error::Serialization) => {}
                    // A well-formed but un-reconcilable file (a *different*
                    // vault's key, or we're locked): refuse rather than
                    // destroy a vault we can't safely merge.
                    Err(e) => return Err(e.into()),
                }
            }
        }
        let bytes = vault.to_bytes()?;
        // Snapshot before the merged result lands: a merge that pulled in a bad
        // peer state is exactly what you want to roll back.
        let _ = snapshot::capture(&self.path);
        self.write_and_mirror(&bytes)?;
        Ok(merged)
    }

    /// Import durable encrypted snapshots written by the sandboxed macOS
    /// provider. A snapshot is acknowledged only after both the canonical file
    /// and its AutoFill mirror contain it. Failed imports remain retryable.
    pub fn import_autofill_registrations(&self, vault: &mut Vault) -> Result<usize> {
        let Some(mirror) = &self.mirror else {
            return Ok(0);
        };
        let Some(container) = mirror.parent() else {
            return Ok(0);
        };
        let inbox = container.join("passkey-inbox");
        if !inbox.exists() {
            return Ok(0);
        }
        // Same lock as VaultShared.acquireVaultLock. Never acquire this from
        // inside save_synced: the order here is shared lock, then canonical.
        let shared_store = VaultStore::new(mirror, "unused", "unused");
        let _shared_lock = shared_store.acquire_write_lock()?;
        let mut paths = std::fs::read_dir(&inbox)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<std::io::Result<Vec<_>>>()?;
        paths.retain(|path| path.extension().is_some_and(|ext| ext == "vault"));
        paths.sort();
        if paths.is_empty() {
            return Ok(0);
        }
        // Stage the entire batch so corrupt/foreign input cannot partially
        // alter the live session. merge_remote authenticates every snapshot.
        let mut candidate = vault.clone();
        for path in &paths {
            candidate.merge_remote(&read_vault_file(path)?)?;
        }
        self.save_synced(&mut candidate)?;
        // save_synced's mirror is best effort; acknowledgment is not.
        write_atomic(mirror, &candidate.to_bytes()?)?;
        *vault = candidate;
        for path in &paths {
            std::fs::remove_file(path)?;
        }
        Ok(paths.len())
    }

    // ----- quick unlock ---------------------------------------------------

    /// Whether a device key is present in the OS keychain. Uses a presence-only
    /// check so it never triggers the biometric prompt (unlike reading the key).
    pub fn quick_unlock_available(&self) -> bool {
        keychain::exists(&self.keychain_service, &self.keychain_account)
    }

    /// Whether quick unlock is STALE for `vault`: the header carries a
    /// device-unlock slot, but the OS-keychain key is missing or no longer
    /// unwraps it (drift from an interrupted re-enable, a restored/bootstrapped
    /// vault file, or a peer's header). Touch ID then succeeds while the unlock
    /// itself fails — callers should repair by re-running
    /// [`enable_quick_unlock`](Self::enable_quick_unlock) once the vault is
    /// unlocked with the master password, and persisting.
    pub fn quick_unlock_stale(&self, vault: &Vault) -> bool {
        if !vault.has_device_unlock() {
            return false;
        }
        match keychain::get(&self.keychain_service, &self.keychain_account) {
            Ok(Some(key)) => !vault.device_key_matches(&key),
            Ok(None) => true,
            // Keychain unreadable: can't verify — don't churn the key.
            Err(_) => false,
        }
    }

    /// Enable quick-unlock: mint a random device key, store it in the OS
    /// keychain, and add a device-wrapped vault key to the header. The caller
    /// must [`save`](Self::save) afterward to persist the header change. The
    /// vault must be unlocked.
    pub fn enable_quick_unlock(&self, vault: &mut Vault) -> Result<()> {
        let device_key = SymmetricKey::generate()?;
        keychain::set(&self.keychain_service, &self.keychain_account, &device_key)?;
        vault.enable_device_unlock(&device_key)?;
        Ok(())
    }

    /// Unlock the vault using the keychain device key (no master password).
    pub fn quick_unlock(&self, vault: &mut Vault) -> Result<()> {
        let device_key = keychain::get(&self.keychain_service, &self.keychain_account)?
            .ok_or(Error::QuickUnlockNotEnabled)?;
        vault.unlock_with_device_key(&device_key)?;
        Ok(())
    }

    /// The device key quick unlock uses, if it is enabled.
    ///
    /// Exposed for exactly one caller: the macOS AutoFill extension runs
    /// sandboxed and cannot read this keychain, so the app mirrors the same key
    /// into the shared access group the extension *can* read (see
    /// `vault-sharedkey`). Handing out the key is not a widening of exposure —
    /// it is already in this process on every quick unlock — but it is not a
    /// general-purpose accessor either. Callers must not persist it anywhere
    /// the OS keychain is not already protecting.
    pub fn device_key(&self) -> Result<Option<SymmetricKey>> {
        keychain::get(&self.keychain_service, &self.keychain_account)
    }

    /// Retire the legacy device key without changing the vault header. Used
    /// only after a protected replacement has been verified and committed.
    pub fn clear_device_key(&self) -> Result<()> {
        keychain::delete(&self.keychain_service, &self.keychain_account)
    }

    /// Disable quick-unlock: delete the keychain device key and clear the
    /// header. The caller must [`save`](Self::save) afterward.
    pub fn disable_quick_unlock(&self, vault: &mut Vault) -> Result<()> {
        if !vault.is_unlocked() {
            return Err(vault_core::Error::Locked.into());
        }
        keychain::delete(&self.keychain_service, &self.keychain_account)?;
        vault.disable_device_unlock()?;
        Ok(())
    }
}

/// Copy a vault using only its path. Background callers can release their
/// application-state lock before a potentially slow external-drive write.
pub fn export_backup_file(source: &Path, destination: &Path) -> Result<u64> {
    let bytes = read_vault_file(source)?;
    Vault::from_bytes(&bytes)?;
    if destination == source
        || (destination.exists() && destination.canonicalize()? == source.canonicalize()?)
    {
        return Err(std::io::Error::other("Choose a different backup path.").into());
    }
    write_atomic(destination, &bytes)?;
    if read_vault_file(destination)? != bytes {
        return Err(std::io::Error::other("Backup verification failed.").into());
    }
    Ok(bytes.len() as u64)
}

/// Monotonic counter to make temp filenames unique within a process.
static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// How many times a blocked rename is retried before the save is reported as
/// failed. Four attempts spread over ~200ms.
const RENAME_ATTEMPTS: u32 = 5;

/// Whether a failed rename is the kind Windows raises when another process has
/// the destination open — worth retrying — rather than a real error.
///
/// 5 = ERROR_ACCESS_DENIED, 32 = ERROR_SHARING_VIOLATION, 33 = ERROR_LOCK_VIOLATION.
#[cfg(windows)]
fn is_transient_rename_error(e: &std::io::Error) -> bool {
    matches!(e.raw_os_error(), Some(5) | Some(32) | Some(33))
}

/// Unix renames over open files, so a failure there is never this kind and the
/// retry loop must not disguise it.
#[cfg(not(windows))]
fn is_transient_rename_error(_e: &std::io::Error) -> bool {
    false
}

/// Atomically replace `path`'s contents with `bytes`.
///
/// Writes to a sibling temp file (so it lands on the same filesystem, making
/// `rename` atomic), restricts its permissions, fsyncs the file, renames it
/// over the target, then best-effort fsyncs the directory.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
    if let Some(dir) = dir {
        fs::create_dir_all(dir)?;
    }
    let dir = dir.unwrap_or_else(|| Path::new("."));

    let file_name = path.file_name().and_then(|s| s.to_str()).unwrap_or("vault");
    let seq = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp = dir.join(format!(".{file_name}.tmp.{}.{seq}", std::process::id()));

    // Reserve the temp path exclusively. A pre-existing file is not ours to
    // overwrite or clean up (including after a recycled process id).
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(&tmp)?;
    let result = (|| -> std::io::Result<()> {
        file.write_all(bytes)?;
        file.flush()?;
        file.sync_all()?;
        Ok(())
    })();
    // Windows cannot rename an open file without sharing-delete access.
    drop(file);

    if let Err(e) = result {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }

    // Windows refuses to replace a destination another process holds open, and
    // on a desktop there is always someone reaching for a file that was just
    // written: Defender, the search indexer, a cloud-sync client — and Arca
    // syncs the vault to Drive, so one is guaranteed to be nearby. The block is
    // transient; those handles are taken to read the file and dropped again in
    // milliseconds. Without this the save surfaced as a bare "internal" error
    // and the password the user had just typed was rolled back and lost.
    //
    // Unix renames over open files regardless, and `is_transient_rename_error`
    // is `false` there, so this loop never spins on those platforms.
    let mut attempt = 0u32;
    loop {
        match fs::rename(&tmp, path) {
            Ok(()) => break,
            Err(e) => {
                attempt += 1;
                if attempt >= RENAME_ATTEMPTS || !is_transient_rename_error(&e) {
                    let _ = fs::remove_file(&tmp);
                    return Err(e);
                }
                // 20ms, 40ms, 60ms, 80ms: 200ms total, under the threshold
                // where a save feels like it stalled, and far longer than a
                // scanner keeps a handle.
                std::thread::sleep(Duration::from_millis(u64::from(20 * attempt)));
            }
        }
    }

    // Durability: fsync the directory so the rename survives a crash. Best
    // effort — not all platforms permit/require it.
    #[cfg(unix)]
    {
        if let Ok(d) = fs::File::open(dir) {
            let _ = d.sync_all();
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_core::{Item, KdfParams, VaultItem};

    fn cheap_params() -> KdfParams {
        KdfParams {
            algorithm: vault_core::KdfAlgorithm::Argon2id,
            m_cost_kib: 256,
            t_cost: 1,
            p_cost: 1,
            salt: vec![3u8; KdfParams::SALT_LEN],
        }
    }

    fn login() -> VaultItem {
        VaultItem::Login {
            title: "Fastmail".into(),
            username: "alice@example.test".into(),
            password: "s3cret".into(),
            url: "https://fastmail.com".into(),
            totp_secret: None,
            notes: String::new(),
        }
    }

    #[test]
    fn autofill_inbox_survives_mirror_refresh_and_imports_after_restart() {
        let dir = tempfile::tempdir().unwrap();
        let mirror = dir.path().join("container/default.vault");
        let inbox = mirror.parent().unwrap().join("passkey-inbox");
        std::fs::create_dir_all(&inbox).unwrap();
        let store =
            VaultStore::new(dir.path().join("main.vault"), "test", "test").with_mirror(&mirror);
        let mut desktop = Vault::create("pw", cheap_params()).unwrap();
        store.save(&desktop).unwrap();
        let mut extension = desktop.clone();
        let native_item = Item::new(login(), 1);
        let native_id = native_item.id;
        extension.upsert_item(native_item).unwrap();
        let pending = inbox.join("registration.vault");
        write_atomic(&pending, &extension.to_bytes().unwrap()).unwrap();
        let local_item = Item::new(login(), 2);
        let local_id = local_item.id;
        desktop.upsert_item(local_item).unwrap();
        store.save_synced(&mut desktop).unwrap();
        assert!(store.refresh_mirror());
        let mut restarted = store.load().unwrap();
        restarted.unlock("pw").unwrap();
        assert_eq!(
            store.import_autofill_registrations(&mut restarted).unwrap(),
            1
        );
        assert!(restarted.get_item(native_id).is_ok());
        assert!(restarted.get_item(local_id).is_ok());
        assert!(!pending.exists());
        let mut persisted = store.load().unwrap();
        persisted.unlock("pw").unwrap();
        assert!(persisted.get_item(native_id).is_ok());
        assert_eq!(
            store.import_autofill_registrations(&mut persisted).unwrap(),
            0
        );
    }

    #[test]
    fn invalid_autofill_inbox_does_not_change_or_acknowledge_anything() {
        let dir = tempfile::tempdir().unwrap();
        let mirror = dir.path().join("container/default.vault");
        let inbox = mirror.parent().unwrap().join("passkey-inbox");
        std::fs::create_dir_all(&inbox).unwrap();
        let store =
            VaultStore::new(dir.path().join("main.vault"), "test", "test").with_mirror(&mirror);
        let mut vault = Vault::create("pw", cheap_params()).unwrap();
        store.save(&vault).unwrap();
        let before = std::fs::read(store.path()).unwrap();
        let foreign = Vault::create("other", cheap_params()).unwrap();
        let pending = inbox.join("foreign.vault");
        write_atomic(&pending, &foreign.to_bytes().unwrap()).unwrap();
        assert!(store.import_autofill_registrations(&mut vault).is_err());
        assert!(pending.exists());
        assert_eq!(std::fs::read(store.path()).unwrap(), before);
        assert!(vault.list_items(false).unwrap().is_empty());
    }

    #[test]
    fn the_mirror_tracks_every_save_path() {
        // Both save paths, because the bug this guards against was one of them
        // bypassing the mirror: a cloud-sync merge went through `save_synced`
        // and left the macOS AutoFill extension serving the pre-merge vault —
        // it filled a password that had already been changed on another device,
        // and the site simply bounced back to its login form.
        let dir = tempfile::tempdir().unwrap();
        let mirror = dir.path().join("container/default.vault");
        std::fs::create_dir_all(mirror.parent().unwrap()).unwrap();
        let store = VaultStore::new(dir.path().join("test.vault"), "test.svc", "test.acct")
            .with_mirror(&mirror);

        let mut v = Vault::create("pw", cheap_params()).unwrap();
        store.save(&v).unwrap();
        assert_eq!(
            std::fs::read(store.path()).unwrap(),
            std::fs::read(&mirror).unwrap(),
            "save() must reach the mirror"
        );

        v.upsert_item(Item::new(login(), 42)).unwrap();
        store.save_synced(&mut v).unwrap();
        assert_eq!(
            std::fs::read(store.path()).unwrap(),
            std::fs::read(&mirror).unwrap(),
            "save_synced() must reach the mirror too"
        );
    }

    #[test]
    fn a_store_without_a_mirror_writes_only_vault_and_lock_file() {
        // Every non-macOS platform, and macOS before the container resolves.
        let dir = tempfile::tempdir().unwrap();
        let store = VaultStore::new(dir.path().join("test.vault"), "test.svc", "test.acct");
        store
            .save(&Vault::create("pw", cheap_params()).unwrap())
            .unwrap();
        let files: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
        assert_eq!(files.len(), 2, "only the vault and its writer lock");
    }

    #[test]
    fn save_then_load_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let store = VaultStore::new(dir.path().join("test.vault"), "test.svc", "test.acct");
        assert!(!store.exists());

        let mut v = Vault::create("pw", cheap_params()).unwrap();
        let item = Item::new(login(), 42);
        let id = item.id;
        v.upsert_item(item).unwrap();
        store.save(&v).unwrap();
        assert!(store.exists());

        let mut loaded = store.load().unwrap();
        loaded.unlock("pw").unwrap();
        assert_eq!(loaded.get_item(id).unwrap().data.title(), "Fastmail");
    }

    #[test]
    fn save_synced_merges_a_peers_external_change() {
        let dir = tempfile::tempdir().unwrap();
        let store = VaultStore::new(dir.path().join("v.vault"), "s", "a");

        // Our copy has item A; save it (records the file fingerprint).
        let mut v = Vault::create("pw", cheap_params()).unwrap();
        v.upsert_item(Item::new(login(), 10)).unwrap();
        store.save(&v).unwrap();

        // A synced peer loads the same file, adds B, and writes it directly to
        // the path — behind our store's back.
        let peer_bytes = {
            let mut peer = Vault::from_bytes(&std::fs::read(store.path()).unwrap()).unwrap();
            peer.unlock("pw").unwrap();
            peer.upsert_item(Item::new(login(), 20)).unwrap(); // B: fresh id
            peer.to_bytes().unwrap()
        };
        std::fs::write(store.path(), &peer_bytes).unwrap();

        // Saving now detects the external change and merges B into our vault
        // instead of clobbering it.
        assert!(store.save_synced(&mut v).unwrap());
        let mut reloaded = store.load().unwrap();
        reloaded.unlock("pw").unwrap();
        assert_eq!(reloaded.list_items(true).unwrap().len(), 2);

        // No external change since -> no merge.
        assert!(!store.save_synced(&mut v).unwrap());
    }

    #[test]
    fn save_synced_replaces_a_corrupt_file_but_refuses_a_foreign_vault() {
        let dir = tempfile::tempdir().unwrap();
        let store = VaultStore::new(dir.path().join("v.vault"), "s", "a");
        let mut v = Vault::create("pw", cheap_params()).unwrap();
        v.upsert_item(Item::new(login(), 10)).unwrap();
        store.save(&v).unwrap();

        // A corrupt / partial file (e.g. a cloud daemon mid-write) must NOT
        // wedge saving — it's not a real vault, so we replace it.
        std::fs::write(store.path(), b"not a vault at all").unwrap();
        assert!(!store.save_synced(&mut v).unwrap());
        let mut reloaded = store.load().unwrap();
        reloaded.unlock("pw").unwrap();
        assert_eq!(reloaded.list_items(true).unwrap().len(), 1);

        // But a well-formed DIFFERENT vault (foreign key) is refused, not
        // clobbered.
        let foreign = {
            let mut other = Vault::create("pw", cheap_params()).unwrap();
            other.upsert_item(Item::new(login(), 5)).unwrap();
            other.to_bytes().unwrap()
        };
        std::fs::write(store.path(), &foreign).unwrap();
        assert!(store.save_synced(&mut v).is_err());
    }

    #[test]
    fn save_overwrites_atomically_without_leaving_temp_files() {
        let dir = tempfile::tempdir().unwrap();
        let store = VaultStore::new(dir.path().join("v.vault"), "s", "a");

        let mut v = Vault::create("pw", cheap_params()).unwrap();
        store.save(&v).unwrap();
        v.upsert_item(Item::new(login(), 1)).unwrap();
        store.save(&v).unwrap(); // overwrite

        // The vault file and the snapshot directory remain; no leftover ".tmp"
        // siblings from either the vault write or the snapshot copy.
        let mut entries: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        entries.sort();
        assert_eq!(
            entries,
            vec![
                "snapshots".to_string(),
                "v.vault".to_string(),
                "v.vault.lock".to_string(),
            ]
        );
        assert!(
            fs::read_dir(dir.path().join("snapshots"))
                .unwrap()
                .all(|e| !e.unwrap().file_name().to_string_lossy().contains(".tmp.")),
            "a torn temp file was left in the snapshot dir"
        );
    }

    #[test]
    fn load_rejects_garbage() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.vault");
        fs::write(&path, b"definitely not a vault").unwrap();
        let store = VaultStore::new(path, "s", "a");
        assert!(store.load().is_err());
    }

    #[test]
    fn load_rejects_an_oversized_file_before_reading_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("huge.vault");
        let file = File::create(&path).unwrap();
        // Sparse on normal filesystems, so the test consumes no 128 MiB buffer.
        file.set_len(vault_core::MAX_VAULT_BYTES as u64 + 1)
            .unwrap();
        let store = VaultStore::new(path, "s", "a");
        assert!(matches!(
            store.load(),
            Err(Error::Core(vault_core::Error::Format))
        ));
    }

    #[test]
    fn write_lock_is_shared_by_independent_store_instances() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.vault");
        let first = VaultStore::new(&path, "s", "a");
        let second = VaultStore::new(&path, "s", "a");

        let held = first.acquire_write_lock().unwrap();
        let contender = second.open_write_lock().unwrap();
        // Compare against fs2's own contended error rather than a hardcoded
        // ErrorKind. Unix reports EWOULDBLOCK, which Rust maps to WouldBlock;
        // Windows reports ERROR_LOCK_VIOLATION, which it does not map to
        // anything, so `.kind()` there is `Uncategorized` and the old
        // assertion could only ever fail on Windows. Raw OS error, because
        // that is the part that is actually comparable on both.
        assert_eq!(
            fs2::FileExt::try_lock_exclusive(&contender)
                .unwrap_err()
                .raw_os_error(),
            fs2::lock_contended_error().raw_os_error(),
            "a second store must see the lock as contended, not as some other error"
        );
        drop(held);
        fs2::FileExt::try_lock_exclusive(&contender).unwrap();
    }

    // Keychain tests require a real OS secret store (and may pop a biometric /
    // auth prompt), so they are not run by default. Run on a desktop with:
    //   cargo test -p vault-store -- --ignored

    // Regression: the keychain device key drifting from the header wrap used to
    // make EVERY unlock fail after a successful Touch ID (prompt storm →
    // password), with nothing repairing it. `quick_unlock_stale` must detect
    // the drift, and re-running `enable_quick_unlock` must repair it.
    #[test]
    #[ignore = "requires OS keychain access"]
    fn stale_device_key_is_detected_and_repairable() {
        let dir = tempfile::tempdir().unwrap();
        let store = VaultStore::new(
            dir.path().join("stale.vault"),
            "no.sybr.vault.test",
            "stale-key-test",
        );
        let mut v = Vault::create("pw", cheap_params()).unwrap();

        // Healthy: enabled, key matches.
        store.enable_quick_unlock(&mut v).unwrap();
        assert!(!store.quick_unlock_stale(&v));

        // Drift: something replaces the keychain copy (interrupted re-enable,
        // another install) — header still wraps the OLD key.
        let intruder = SymmetricKey::generate().unwrap();
        keychain::set("no.sybr.vault.test", "stale-key-test", &intruder).unwrap();
        assert!(store.quick_unlock_stale(&v));
        let mut locked = Vault::from_bytes(&v.to_bytes().unwrap()).unwrap();
        assert!(store.quick_unlock(&mut locked).is_err()); // the user-visible failure

        // Repair (what the password-unlock self-heal runs): fresh key, rewrap.
        store.enable_quick_unlock(&mut v).unwrap();
        assert!(!store.quick_unlock_stale(&v));
        let mut reloaded = Vault::from_bytes(&v.to_bytes().unwrap()).unwrap();
        store.quick_unlock(&mut reloaded).unwrap();
        assert!(reloaded.is_unlocked());

        // Missing key entirely is also stale (heal covers both).
        keychain::delete("no.sybr.vault.test", "stale-key-test").unwrap();
        assert!(store.quick_unlock_stale(&v));

        // Cleanup: nothing left behind.
        let mut v2 = v;
        let _ = store.disable_quick_unlock(&mut v2);
    }

    #[test]
    #[ignore = "requires OS keychain access"]
    fn quick_unlock_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let store = VaultStore::new(
            dir.path().join("qu.vault"),
            "no.sybr.vault.test",
            "quick-unlock-test",
        );
        let mut v = Vault::create("pw", cheap_params()).unwrap();
        v.upsert_item(Item::new(login(), 1)).unwrap();
        store.enable_quick_unlock(&mut v).unwrap();
        store.save(&v).unwrap();

        let mut loaded = store.load().unwrap();
        store.quick_unlock(&mut loaded).unwrap();
        assert!(loaded.is_unlocked());

        store.disable_quick_unlock(&mut loaded).unwrap();
        assert!(!store.quick_unlock_available());
    }

    #[test]
    fn fingerprint_is_deterministic_and_sensitive_to_content() {
        let a = b"test payload 1";
        let b = b"test payload 2";
        assert_eq!(fingerprint(a), fingerprint(a));
        assert_ne!(fingerprint(a), fingerprint(b));
    }
}
