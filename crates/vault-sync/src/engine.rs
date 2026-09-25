//! The pull → merge → push cycle.
//!
//! Ported unchanged from the desktop implementation, which had been reviewed
//! adversarially; the point of moving it was never to redesign it. What is new
//! is that [`RemoteStore`] and [`LocalVault`] are traits, so the decisions below
//! can finally be tested against a fake instead of a Google account.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{CycleError, LocalError, LocalVault, RemoteStore, SyncObserver};

/// What the UI shows.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncStatus {
    pub pending: bool,
    pub syncing: bool,
    pub connected: bool,
    pub account: Option<String>,
    pub last_sync_unix: Option<u64>,
    pub last_error: Option<String>,
}

#[derive(Default)]
struct EngineState {
    account: Option<String>,
    last_sync_unix: Option<u64>,
    last_error: Option<String>,
    /// Checksum of remote content we last integrated OR produced ourselves.
    /// Set **only** from our own upload response — see the crate docs.
    last_remote_checksum: Option<String>,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub struct SyncEngine {
    remote: Arc<dyn RemoteStore>,
    local: Arc<dyn LocalVault>,
    observer: Arc<dyn SyncObserver>,
    state: Mutex<EngineState>,
    /// Local changes waiting to be pushed. Set by every persist; cleared only
    /// after an upload actually succeeds.
    dirty: AtomicBool,
    /// One cycle at a time, across the background loop and any manual trigger.
    in_flight: AtomicBool,
}

impl SyncEngine {
    pub fn new(
        remote: Arc<dyn RemoteStore>,
        local: Arc<dyn LocalVault>,
        observer: Arc<dyn SyncObserver>,
    ) -> Self {
        Self {
            remote,
            local,
            observer,
            state: Mutex::new(EngineState::default()),
            // Starts dirty: the first cycle after launch must push or bootstrap.
            dirty: AtomicBool::new(true),
            in_flight: AtomicBool::new(false),
        }
    }

    /// Local vault state changed and should be pushed on the next cycle.
    pub fn mark_dirty(&self) {
        self.dirty.store(true, Ordering::Relaxed);
        self.observer.status_changed(&self.status());
    }

    /// Record the signed-in account label, and reset the previous account's
    /// bookkeeping — a checksum from someone else's Drive means nothing here.
    pub fn set_account(&self, account: Option<String>) {
        if let Ok(mut s) = self.state.lock() {
            *s = EngineState {
                account,
                ..EngineState::default()
            };
        }
        self.mark_dirty();
    }

    pub fn forget_account(&self) {
        if let Ok(mut s) = self.state.lock() {
            *s = EngineState::default();
        }
        self.observer.status_changed(&self.status());
    }

    pub fn status(&self) -> SyncStatus {
        let connected = self.remote.is_connected();
        let guard = self.state.lock().ok();
        SyncStatus {
            pending: self.dirty.load(Ordering::Relaxed),
            syncing: self.in_flight.load(Ordering::Acquire),
            connected,
            account: guard.as_ref().and_then(|g| g.account.clone()),
            last_sync_unix: guard.as_ref().and_then(|g| g.last_sync_unix),
            last_error: guard.as_ref().and_then(|g| g.last_error.clone()),
        }
    }

    /// Run one sync now. Returns whether remote changes were merged.
    ///
    /// At most one cycle runs at a time; a conflict re-runs and an expired
    /// credential refreshes once, both bounded.
    pub fn sync_now(&self) -> Result<bool, String> {
        if !self.remote.is_connected() {
            return Ok(false);
        }
        if self.in_flight.swap(true, Ordering::Acquire) {
            // Another cycle is running and will pick our changes up.
            return Ok(false);
        }
        // Cleared on drop rather than after the call, so a panic inside the
        // cycle cannot leave the flag set. It would not crash anything — the
        // FFI catches it — but every later sync would return "already running"
        // and do nothing, forever, with no way back short of a restart. A
        // silent permanent stop is the worst shape a sync failure can take.
        let flight = InFlight(&self.in_flight);
        self.observer.status_changed(&self.status());

        let result = self.attempt_cycles();

        match &result {
            Ok(merged) => {
                if *merged {
                    self.observer.merged();
                }
            }
            Err(e) => {
                if let Ok(mut s) = self.state.lock() {
                    s.last_error = Some(e.clone());
                }
            }
        }
        drop(flight);
        self.observer.status_changed(&self.status());
        result
    }

    fn attempt_cycles(&self) -> Result<bool, String> {
        let mut auth_retried = false;
        for _attempt in 0..3 {
            match self.cycle() {
                Ok(merged) => return Ok(merged),
                // A peer raced us: re-pull rather than clobber their write.
                Err(CycleError::Conflict) => continue,
                Err(CycleError::Auth) if !auth_retried => {
                    auth_retried = true;
                    self.remote.invalidate_auth();
                    continue;
                }
                Err(CycleError::Auth) => {
                    return Err("Google sign-in expired — reconnect in Settings".into())
                }
                Err(CycleError::Other(m)) => return Err(m),
            }
        }
        Err("sync kept conflicting with another device — will retry".into())
    }

    /// One pull → merge → push attempt.
    fn cycle(&self) -> Result<bool, CycleError> {
        // Every remote copy, oldest first. An error is surfaced, never treated
        // as "no file" — a silent failure here caused duplicate creation.
        let remotes = self.remote.list()?;
        let primary = remotes.first().cloned();
        let duplicates: Vec<_> = remotes.iter().skip(1).cloned().collect();

        let known = {
            let guard = self
                .state
                .lock()
                .map_err(|_| CycleError::Other("sync state poisoned".into()))?;
            guard.last_remote_checksum.clone()
        };

        // Skip a download we can prove we already integrated; pull everything
        // else. `known` only ever came from our own upload, so a peer's write
        // can never be skipped here.
        let mut to_merge: Vec<Vec<u8>> = Vec::new();
        let mut based_on: Option<String> = None;
        if let Some(file) = &primary {
            if Some(&file.checksum) != known.as_ref() {
                to_merge.push(self.remote.download(&file.id)?);
            }
            based_on = Some(file.checksum.clone());
        }
        for file in &duplicates {
            to_merge.push(self.remote.download(&file.id)?);
        }

        let dirty = self.dirty.swap(false, Ordering::Relaxed);
        let merged_any = !to_merge.is_empty();

        // Nothing new remotely, nothing changed locally, and the remote exists:
        // a genuine no-op. Uploading here would rewrite the file every tick.
        if !merged_any && !dirty && primary.is_some() {
            if let Ok(mut s) = self.state.lock() {
                s.last_sync_unix = Some(now_unix());
                s.last_error = None;
            }
            return Ok(false);
        }

        // The flag is now consumed, so from here every failure has to put it
        // back — it stood for local changes that still have not been pushed,
        // and dropping it means the remote silently stays behind until the user
        // happens to edit something else. The desktop version re-flagged on
        // some of these paths and not others; doing it in one place is what
        // makes that uniform.
        let outcome = self.merge_and_push(&to_merge, primary.as_ref(), based_on, &duplicates);
        if dirty && !matches!(outcome, Ok(Pushed::Yes)) {
            self.mark_dirty();
        }
        match outcome {
            Ok(Pushed::Yes) => Ok(merged_any),
            // Deferring is not failing: a locked vault stays a quiet no-op,
            // exactly as it was before the extraction.
            Ok(Pushed::Deferred) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Merge, preflight, push, tidy.
    fn merge_and_push(
        &self,
        to_merge: &[Vec<u8>],
        primary: Option<&crate::RemoteFile>,
        based_on: Option<String>,
        duplicates: &[crate::RemoteFile],
    ) -> Result<Pushed, CycleError> {
        let out_bytes = match self.local.merge_and_serialize(to_merge) {
            Ok(bytes) => bytes,
            Err(LocalError::Locked) => return Ok(Pushed::Deferred),
            Err(e) => return Err(CycleError::Other(e.to_string())),
        };

        // Preflight: if the remote moved since our download, re-run the whole
        // cycle instead of overwriting content we have not merged.
        if let (Some(file), Some(based)) = (primary, &based_on) {
            if &self.remote.checksum(&file.id)? != based {
                // Unconditional: a merge we have not pushed still needs pushing
                // even when there were no local edits behind this cycle.
                self.mark_dirty();
                return Err(CycleError::Conflict);
            }
        }

        let uploaded = match self.remote.upload(None, &out_bytes) {
            Ok(file) => file,
            Err(e) => {
                self.mark_dirty(); // nothing was written; keep the flag
                return Err(e);
            }
        };

        // Publish a new immutable file before retiring the exact inputs we
        // merged. Two devices can both pass preflight: replacing the primary
        // would lose one upload. Distinct new ids leave both revisions for the
        // next cycle to merge, even if either process stops immediately.
        for file in primary.into_iter().chain(duplicates) {
            self.remote.delete(&file.id)?;
        }

        if let Ok(mut s) = self.state.lock() {
            s.last_remote_checksum = Some(uploaded.checksum);
            s.last_sync_unix = Some(now_unix());
            s.last_error = None;
        }
        Ok(Pushed::Yes)
    }
}

/// Holds the one-cycle-at-a-time flag and releases it however the cycle ends.
struct InFlight<'a>(&'a AtomicBool);

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// Whether the push half of a cycle actually wrote anything.
enum Pushed {
    Yes,
    /// The vault was locked, so there was nothing to serialize. Not a failure —
    /// the engine backs off and the caller's pending changes are kept.
    Deferred,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    /// An in-memory remote. The whole reason the engine was extracted: these
    /// decisions used to be reachable only through a Google account.
    #[derive(Default)]
    struct FakeRemote {
        files: Mutex<Vec<crate::RemoteFile>>,
        contents: Mutex<Vec<(String, Vec<u8>)>>,
        uploads: AtomicUsize,
        downloads: AtomicUsize,
        deletes: AtomicUsize,
        /// Rewrites the primary's checksum during the preflight, standing in for
        /// a peer that uploaded between our download and our push.
        peer_writes_at_preflight: AtomicBool,
        fail_auth_once: AtomicBool,
        /// A transport blip during the preflight — the network failing at the
        /// least convenient moment, after the dirty flag has been consumed.
        fail_checksum_once: AtomicBool,
        /// Pause the first two uploads after preflight, modelling two devices
        /// that both read the same remote before either writes.
        upload_barrier: Option<Arc<std::sync::Barrier>>,
    }

    impl FakeRemote {
        fn with_file(id: &str, checksum: &str, body: &[u8]) -> Self {
            let remote = FakeRemote::default();
            remote.files.lock().unwrap().push(crate::RemoteFile {
                id: id.into(),
                checksum: checksum.into(),
            });
            remote
                .contents
                .lock()
                .unwrap()
                .push((id.into(), body.to_vec()));
            remote
        }
        fn uploads(&self) -> usize {
            self.uploads.load(Ordering::SeqCst)
        }
        fn downloads(&self) -> usize {
            self.downloads.load(Ordering::SeqCst)
        }
    }

    impl RemoteStore for FakeRemote {
        fn is_connected(&self) -> bool {
            true
        }
        fn list(&self) -> Result<Vec<crate::RemoteFile>, CycleError> {
            if self.fail_auth_once.swap(false, Ordering::SeqCst) {
                return Err(CycleError::Auth);
            }
            Ok(self.files.lock().unwrap().clone())
        }
        fn download(&self, id: &str) -> Result<Vec<u8>, CycleError> {
            self.downloads.fetch_add(1, Ordering::SeqCst);
            self.contents
                .lock()
                .unwrap()
                .iter()
                .find(|(fid, _)| fid == id)
                .map(|(_, b)| b.clone())
                .ok_or_else(|| CycleError::Other("no such file".into()))
        }
        fn checksum(&self, id: &str) -> Result<String, CycleError> {
            if self.fail_checksum_once.swap(false, Ordering::SeqCst) {
                return Err(CycleError::Other(
                    "preflight failed: connection reset".into(),
                ));
            }
            if self.peer_writes_at_preflight.swap(false, Ordering::SeqCst) {
                return Ok("moved-under-us".into());
            }
            self.files
                .lock()
                .unwrap()
                .iter()
                .find(|f| f.id == id)
                .map(|f| f.checksum.clone())
                .ok_or_else(|| CycleError::Other("no such file".into()))
        }
        fn delete(&self, id: &str) -> Result<(), CycleError> {
            self.deletes.fetch_add(1, Ordering::SeqCst);
            self.files.lock().unwrap().retain(|f| f.id != id);
            Ok(())
        }
        fn upload(
            &self,
            existing: Option<&str>,
            bytes: &[u8],
        ) -> Result<crate::RemoteFile, CycleError> {
            let n = self.uploads.fetch_add(1, Ordering::SeqCst) + 1;
            if n <= 2 {
                if let Some(barrier) = &self.upload_barrier {
                    barrier.wait();
                }
            }
            let id = existing
                .map(str::to_string)
                .unwrap_or_else(|| format!("new-{n}"));
            let file = crate::RemoteFile {
                id: id.clone(),
                checksum: format!("md5-after-upload-{n}"),
            };
            let mut files = self.files.lock().unwrap();
            files.retain(|f| f.id != id);
            files.insert(0, file.clone());
            let mut contents = self.contents.lock().unwrap();
            contents.retain(|(fid, _)| fid != &id);
            contents.push((id, bytes.to_vec()));
            Ok(file)
        }
    }

    /// A local vault that records what it was asked to merge.
    #[derive(Default)]
    struct FakeLocal {
        merged: Mutex<Vec<Vec<u8>>>,
        locked: AtomicBool,
    }

    impl LocalVault for FakeLocal {
        fn merge_and_serialize(&self, remotes: &[Vec<u8>]) -> Result<Vec<u8>, LocalError> {
            if self.locked.load(Ordering::SeqCst) {
                return Err(LocalError::Locked);
            }
            self.merged.lock().unwrap().extend_from_slice(remotes);
            Ok(b"local-vault-bytes".to_vec())
        }
    }

    fn engine(remote: Arc<FakeRemote>, local: Arc<FakeLocal>) -> SyncEngine {
        SyncEngine::new(remote, local, Arc::new(crate::SilentObserver))
    }

    #[test]
    fn status_tracks_pending_deferred_failed_and_completed_cycles() {
        let remote = Arc::new(FakeRemote::default());
        let local = Arc::new(FakeLocal::default());
        let sync = engine(remote.clone(), local.clone());
        assert!(sync.status().pending);
        local.locked.store(true, Ordering::SeqCst);
        sync.sync_now().unwrap();
        assert!(sync.status().pending);
        assert!(!sync.status().syncing);
        assert!(sync.status().last_sync_unix.is_none());
        local.locked.store(false, Ordering::SeqCst);
        sync.sync_now().unwrap();
        assert!(!sync.status().pending);
        assert!(!sync.status().syncing);
        assert!(sync.status().last_sync_unix.is_some());
        sync.mark_dirty();
        remote.fail_checksum_once.store(true, Ordering::SeqCst);
        assert!(sync.sync_now().is_err());
        assert!(sync.status().pending);
        assert!(!sync.status().syncing);
        assert!(sync.status().last_error.is_some());
    }

    #[test]
    fn bootstraps_when_the_remote_is_empty() {
        let remote = Arc::new(FakeRemote::default());
        let local = Arc::new(FakeLocal::default());
        let sync = engine(remote.clone(), local.clone());

        assert_eq!(
            sync.sync_now(),
            Ok(false),
            "nothing to merge on a bootstrap"
        );
        assert_eq!(
            remote.uploads(),
            1,
            "the first cycle must create the remote"
        );
        assert!(local.merged.lock().unwrap().is_empty());
    }

    #[test]
    fn an_idle_app_does_not_rewrite_the_remote() {
        let remote = Arc::new(FakeRemote::default());
        let local = Arc::new(FakeLocal::default());
        let sync = engine(remote.clone(), local.clone());

        sync.sync_now().unwrap(); // bootstrap: uploads, records its own checksum
        assert_eq!(remote.uploads(), 1);

        // Nothing changed locally, nothing new remotely. Ticking must be a
        // no-op — otherwise the vault is rewritten every 30 seconds forever.
        for _ in 0..5 {
            assert_eq!(sync.sync_now(), Ok(false));
        }
        assert_eq!(remote.uploads(), 1, "idle cycles must not upload");
        assert_eq!(remote.downloads(), 0, "our own upload need not be re-read");
    }

    #[test]
    fn local_changes_are_pushed() {
        let remote = Arc::new(FakeRemote::default());
        let local = Arc::new(FakeLocal::default());
        let sync = engine(remote.clone(), local.clone());
        sync.sync_now().unwrap();

        sync.mark_dirty();
        assert_eq!(sync.sync_now(), Ok(false), "a local edit is not a merge");
        assert_eq!(remote.uploads(), 2);
    }

    #[test]
    fn a_peer_upload_is_downloaded_and_merged() {
        let remote = Arc::new(FakeRemote::with_file("peer", "md5-peer", b"peer-bytes"));
        let local = Arc::new(FakeLocal::default());
        let sync = engine(remote.clone(), local.clone());

        assert_eq!(sync.sync_now(), Ok(true), "a changed remote is a merge");
        assert_eq!(remote.downloads(), 1);
        assert_eq!(local.merged.lock().unwrap()[0], b"peer-bytes".to_vec());
    }

    /// The invariant that stops a peer's write being silently discarded: the
    /// recorded checksum comes only from our own upload, so a listing that
    /// shows a different one is always pulled.
    #[test]
    fn a_checksum_we_did_not_write_is_never_treated_as_integrated() {
        let remote = Arc::new(FakeRemote::default());
        let local = Arc::new(FakeLocal::default());
        let sync = engine(remote.clone(), local.clone());
        sync.sync_now().unwrap(); // we upload; checksum is now ours

        // A peer replaces it behind our back.
        remote.files.lock().unwrap()[0].checksum = "md5-from-a-peer".into();
        remote.contents.lock().unwrap()[0].1 = b"peer-bytes".to_vec();

        assert_eq!(sync.sync_now(), Ok(true));
        assert_eq!(
            local.merged.lock().unwrap().last().unwrap(),
            &b"peer-bytes".to_vec()
        );
    }

    /// A peer writing between our download and our push must not be clobbered.
    #[test]
    fn a_mid_cycle_peer_write_reruns_instead_of_overwriting() {
        let remote = Arc::new(FakeRemote::with_file("peer", "md5-peer", b"peer-bytes"));
        let local = Arc::new(FakeLocal::default());
        remote
            .peer_writes_at_preflight
            .store(true, Ordering::SeqCst);
        let sync = engine(remote.clone(), local.clone());

        // First attempt hits the conflict and retries; the retry succeeds.
        assert!(sync.sync_now().is_ok());
        assert_eq!(remote.uploads(), 1, "the conflicting attempt must not push");
        assert!(
            remote.downloads() >= 2,
            "the retry has to re-pull, not reuse what it had"
        );
    }

    #[test]
    fn duplicate_remotes_are_all_merged_and_the_extras_deleted() {
        let remote = Arc::new(FakeRemote::with_file("oldest", "md5-a", b"copy-a"));
        remote.files.lock().unwrap().push(crate::RemoteFile {
            id: "newer".into(),
            checksum: "md5-b".into(),
        });
        remote
            .contents
            .lock()
            .unwrap()
            .push(("newer".into(), b"copy-b".to_vec()));
        let local = Arc::new(FakeLocal::default());
        let sync = engine(remote.clone(), local.clone());

        assert_eq!(sync.sync_now(), Ok(true));
        let merged = local.merged.lock().unwrap().clone();
        assert!(merged.contains(&b"copy-a".to_vec()));
        assert!(merged.contains(&b"copy-b".to_vec()));
        assert_eq!(
            remote.deletes.load(Ordering::SeqCst),
            2,
            "merged inputs retired"
        );
        assert_eq!(
            remote.files.lock().unwrap().len(),
            1,
            "a single new merged revision remains"
        );
    }

    /// A locked vault must not lose the local changes it could not push.
    #[test]
    fn a_locked_vault_defers_without_dropping_local_changes() {
        let remote = Arc::new(FakeRemote::default());
        let local = Arc::new(FakeLocal::default());
        local.locked.store(true, Ordering::SeqCst);
        let sync = engine(remote.clone(), local.clone());

        assert_eq!(sync.sync_now(), Ok(false));
        assert_eq!(remote.uploads(), 0, "nothing can be pushed while locked");

        // Unlock: the change that could not be pushed must still be pending.
        local.locked.store(false, Ordering::SeqCst);
        assert_eq!(sync.sync_now(), Ok(false));
        assert_eq!(remote.uploads(), 1, "the deferred change was not lost");
    }

    /// A pending local change must survive a failure *after* the dirty flag has
    /// been consumed. Otherwise a transport blip at the wrong moment leaves the
    /// remote quietly behind until the user edits something else — and the app
    /// still reports a successful sync the next tick, because there is nothing
    /// left to say a push is owed.
    #[test]
    fn a_failure_after_the_flag_is_consumed_does_not_drop_the_local_change() {
        let remote = Arc::new(FakeRemote::default());
        let local = Arc::new(FakeLocal::default());
        let sync = engine(remote.clone(), local.clone());
        sync.sync_now().unwrap(); // bootstrap, so a preflight happens from now on
        assert_eq!(remote.uploads(), 1);

        sync.mark_dirty();
        remote.fail_checksum_once.store(true, Ordering::SeqCst);
        assert!(
            sync.sync_now().is_err(),
            "the preflight failure is reported"
        );
        assert_eq!(remote.uploads(), 1, "nothing was pushed");

        // The network is fine again. The edit from before must still be owed.
        assert_eq!(sync.sync_now(), Ok(false));
        assert_eq!(remote.uploads(), 2, "the pending change was not forgotten");
    }

    #[test]
    fn a_rejected_credential_is_retried_once_then_reported() {
        let remote = Arc::new(FakeRemote::default());
        let local = Arc::new(FakeLocal::default());
        remote.fail_auth_once.store(true, Ordering::SeqCst);
        let sync = engine(remote.clone(), local.clone());

        assert!(sync.sync_now().is_ok(), "one auth failure is recoverable");
        assert_eq!(remote.uploads(), 1);
    }

    /// A panic inside a cycle must not wedge the engine. The FFI catches the
    /// panic and reports it, so the user sees one failed sync — but if the
    /// in-flight flag stayed set, every later sync would quietly return
    /// "already running" and the vault would stop syncing for the life of the
    /// process, with nothing on screen to say so.
    #[test]
    fn a_panicking_cycle_does_not_wedge_every_later_sync() {
        struct PanicsOnce {
            armed: AtomicBool,
            inner: FakeRemote,
        }
        impl RemoteStore for PanicsOnce {
            fn is_connected(&self) -> bool {
                true
            }
            fn list(&self) -> Result<Vec<crate::RemoteFile>, CycleError> {
                if self.armed.swap(false, Ordering::SeqCst) {
                    panic!("transport exploded");
                }
                self.inner.list()
            }
            fn download(&self, id: &str) -> Result<Vec<u8>, CycleError> {
                self.inner.download(id)
            }
            fn checksum(&self, id: &str) -> Result<String, CycleError> {
                self.inner.checksum(id)
            }
            fn delete(&self, id: &str) -> Result<(), CycleError> {
                self.inner.delete(id)
            }
            fn upload(
                &self,
                existing: Option<&str>,
                bytes: &[u8],
            ) -> Result<crate::RemoteFile, CycleError> {
                self.inner.upload(existing, bytes)
            }
        }

        let remote = Arc::new(PanicsOnce {
            armed: AtomicBool::new(true),
            inner: FakeRemote::default(),
        });
        let sync = SyncEngine::new(
            remote.clone(),
            Arc::new(FakeLocal::default()),
            Arc::new(crate::SilentObserver),
        );

        // Swallow the panic the way the FFI boundary does.
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| sync.sync_now()));
        std::panic::set_hook(previous);
        assert!(panicked.is_err(), "the cycle really did panic");

        // The engine has to still work.
        assert_eq!(sync.sync_now(), Ok(false));
        assert_eq!(
            remote.inner.uploads(),
            1,
            "a later sync must still run, not report 'already in flight' forever"
        );
    }

    #[test]
    fn a_disconnected_remote_does_nothing() {
        struct Disconnected;
        impl RemoteStore for Disconnected {
            fn is_connected(&self) -> bool {
                false
            }
            fn list(&self) -> Result<Vec<crate::RemoteFile>, CycleError> {
                panic!("must not touch the network while disconnected")
            }
            fn download(&self, _: &str) -> Result<Vec<u8>, CycleError> {
                unreachable!()
            }
            fn checksum(&self, _: &str) -> Result<String, CycleError> {
                unreachable!()
            }
            fn delete(&self, _: &str) -> Result<(), CycleError> {
                unreachable!()
            }
            fn upload(&self, _: Option<&str>, _: &[u8]) -> Result<crate::RemoteFile, CycleError> {
                unreachable!()
            }
        }
        let sync = SyncEngine::new(
            Arc::new(Disconnected),
            Arc::new(FakeLocal::default()),
            Arc::new(crate::SilentObserver),
        );
        assert_eq!(sync.sync_now(), Ok(false));
        assert!(!sync.status().connected);
    }

    #[test]
    fn status_reports_the_account_and_clears_it_on_disconnect() {
        let sync = engine(
            Arc::new(FakeRemote::default()),
            Arc::new(FakeLocal::default()),
        );
        sync.set_account(Some("alice@example.test".into()));
        assert_eq!(sync.status().account.as_deref(), Some("alice@example.test"));

        sync.forget_account();
        assert_eq!(sync.status().account, None);
    }

    #[test]
    fn simultaneous_uploads_preserve_both_devices_edits() {
        use vault_core::{Item, KdfAlgorithm, KdfParams, Vault, VaultItem};
        struct RealLocal(Mutex<Vault>);
        impl LocalVault for RealLocal {
            fn merge_and_serialize(&self, remotes: &[Vec<u8>]) -> Result<Vec<u8>, LocalError> {
                let mut vault = self.0.lock().unwrap();
                crate::merge_remotes(&mut vault, remotes)?;
                vault
                    .to_bytes()
                    .map_err(|e| LocalError::Save(e.to_string()))
            }
        }
        let base = Vault::create(
            "pw",
            KdfParams {
                algorithm: KdfAlgorithm::Argon2id,
                m_cost_kib: 256,
                t_cost: 1,
                p_cost: 1,
                salt: vec![7; 32],
            },
        )
        .unwrap()
        .to_bytes()
        .unwrap();
        let mut remote = FakeRemote::with_file("base", "base-checksum", &base);
        remote.upload_barrier = Some(Arc::new(std::sync::Barrier::new(2)));
        let remote = Arc::new(remote);
        let device = |title: &str| {
            let mut vault = Vault::from_bytes(&base).unwrap();
            vault.unlock("pw").unwrap();
            vault
                .upsert_item(Item::new(
                    VaultItem::SecureNote {
                        title: title.into(),
                        body: "test data".into(),
                    },
                    1,
                ))
                .unwrap();
            let local = Arc::new(RealLocal(Mutex::new(vault)));
            let engine = Arc::new(SyncEngine::new(
                remote.clone(),
                local.clone(),
                Arc::new(crate::SilentObserver),
            ));
            (local, engine)
        };
        let (local_a, a) = device("desktop edit");
        let (_, b) = device("phone edit");
        std::thread::scope(|scope| {
            let first = scope.spawn(|| a.sync_now());
            let second = scope.spawn(|| b.sync_now());
            first.join().unwrap().unwrap();
            second.join().unwrap().unwrap();
        });
        // Both processes could stop now; both edits still exist remotely.
        assert_eq!(remote.files.lock().unwrap().len(), 2);
        a.sync_now().unwrap();
        assert_eq!(remote.files.lock().unwrap().len(), 1);
        let mut titles: Vec<_> = local_a
            .0
            .lock()
            .unwrap()
            .list_items(false)
            .unwrap()
            .into_iter()
            .map(|item| item.title)
            .collect();
        titles.sort();
        assert_eq!(titles, ["desktop edit", "phone edit"]);
    }
}
