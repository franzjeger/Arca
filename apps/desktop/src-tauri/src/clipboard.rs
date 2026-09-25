//! Clipboard owner thread.
//!
//! On X11/Wayland the clipboard has no central store: the *source application*
//! must stay alive and serve the selection to whoever pastes. `arboard`
//! relinquishes ownership when its `Clipboard` is dropped, so creating a fresh
//! `Clipboard` per copy (and dropping it) makes the copied secret vanish before
//! the user can paste on Linux.
//!
//! The fix: one long-lived clipboard backend, owned by a dedicated thread for
//! the app's lifetime, driven over a channel. macOS/Windows keep clipboard data
//! in the OS regardless, so the same code path is correct on all three.
//!
//! Auto-clear keeps the original "clear only if still ours" behavior: after the
//! timeout we re-read the clipboard and wipe it only if it still holds exactly
//! what we put there.
//!
//! The backend is abstracted behind [`ClipboardBackend`] so the owner-thread
//! logic (serves-after-return, clear-only-if-unchanged) can be tested
//! deterministically with an in-memory fake — without clobbering the
//! developer's real clipboard or depending on a display server. A real-arboard
//! smoke test exists but is `#[ignore]`d.

use std::sync::mpsc::{self, Sender};
use std::thread;
use std::time::Duration;

use tauri::{AppHandle, Emitter};

/// Minimal clipboard surface the owner thread needs. Implemented for real by
/// `arboard`, and by an in-memory fake in tests.
trait ClipboardBackend {
    fn set_text(&mut self, text: String);
    fn get_text(&mut self) -> Option<String>;
}

struct ArboardBackend(arboard::Clipboard);

impl ClipboardBackend for ArboardBackend {
    fn set_text(&mut self, text: String) {
        let _ = self.0.set_text(text);
    }
    fn get_text(&mut self) -> Option<String> {
        self.0.get_text().ok()
    }
}

enum ClipCommand {
    Set(String),
    ClearIfUnchanged(String),
    ClearOnLock,
    #[cfg(test)]
    Ping(Sender<()>),
}

/// Cheap, cloneable handle to the clipboard owner thread.
#[derive(Clone)]
pub struct ClipboardManager {
    tx: Sender<ClipCommand>,
}

impl ClipboardManager {
    /// Start the owner thread backed by the real OS clipboard. The single
    /// `arboard::Clipboard` it holds lives until the app exits, preserving
    /// Linux selection ownership. If the clipboard can't be opened, commands
    /// become no-ops. `arboard::Clipboard` is created *inside* the thread (it
    /// is not necessarily `Send`).
    pub fn spawn(app: AppHandle) -> Self {
        Self::with_backend(
            || arboard::Clipboard::new().ok().map(ArboardBackend),
            Box::new(move || {
                let _ = app.emit("clipboard-cleared", ());
            }),
        )
    }

    /// Generic constructor: `make_backend` runs *on the owner thread* (so the
    /// backend need not be `Send`); `on_cleared` is invoked after a successful
    /// auto-clear.
    fn with_backend<B, F>(make_backend: F, on_cleared: Box<dyn Fn() + Send>) -> Self
    where
        B: ClipboardBackend + 'static,
        F: FnOnce() -> Option<B> + Send + 'static,
    {
        let (tx, rx) = mpsc::channel::<ClipCommand>();
        thread::spawn(move || {
            let mut backend = match make_backend() {
                Some(b) => b,
                // Clipboard unavailable: drain so senders never block, do nothing.
                None => {
                    while rx.recv().is_ok() {}
                    return;
                }
            };
            let mut last_set: Option<String> = None;
            while let Ok(cmd) = rx.recv() {
                match cmd {
                    ClipCommand::Set(text) => {
                        last_set = Some(text.clone());
                        backend.set_text(text);
                    }
                    ClipCommand::ClearIfUnchanged(expected) => {
                        if backend.get_text().as_deref() == Some(expected.as_str()) {
                            backend.set_text(String::new());
                            on_cleared();
                            if last_set.as_deref() == Some(expected.as_str()) {
                                last_set = None;
                            }
                        }
                    }
                    ClipCommand::ClearOnLock => {
                        if let Some(expected) = last_set.take() {
                            if backend.get_text().as_deref() == Some(expected.as_str()) {
                                backend.set_text(String::new());
                                on_cleared();
                            }
                        }
                    }
                    #[cfg(test)]
                    ClipCommand::Ping(ack) => {
                        let _ = ack.send(());
                    }
                }
            }
        });
        Self { tx }
    }

    /// Copy `text` to the clipboard and, if `clear_secs > 0`, schedule an
    /// auto-clear that fires only if the clipboard still holds `text`.
    pub fn copy(&self, text: String, clear_secs: u64) {
        let _ = self.tx.send(ClipCommand::Set(text.clone()));
        if clear_secs > 0 {
            let tx = self.tx.clone();
            thread::spawn(move || {
                thread::sleep(Duration::from_secs(clear_secs));
                let _ = tx.send(ClipCommand::ClearIfUnchanged(text));
            });
        }
    }

    /// Clear the clipboard immediately if it still holds the last text Arca copied.
    /// Called when the vault is locked (explicitly or via auto-lock/blur/idle) so
    /// secrets do not remain exposed in the OS clipboard after the session ends.
    pub fn clear_on_lock(&self) {
        let _ = self.tx.send(ClipCommand::ClearOnLock);
    }

    // ---- test seams ------------------------------------------------------

    /// Build a manager backed by an in-memory clipboard plus a probe to observe
    /// it. Deterministic and side-effect-free (no real OS clipboard).
    #[cfg(test)]
    pub(crate) fn memory() -> (Self, ClipboardProbe) {
        use std::sync::atomic::AtomicUsize;
        use std::sync::{Arc, Mutex};

        let store = Arc::new(Mutex::new(None));
        let cleared = Arc::new(AtomicUsize::new(0));
        let backend_store = store.clone();
        let backend_cleared = cleared.clone();
        let mgr = Self::with_backend(
            move || {
                Some(MemoryBackend {
                    store: backend_store,
                })
            },
            Box::new(move || {
                backend_cleared.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }),
        );
        (mgr, ClipboardProbe { store, cleared })
    }

    /// Block until every previously-sent command has been processed (FIFO).
    #[cfg(test)]
    pub(crate) fn sync(&self) {
        let (ack, done) = mpsc::channel();
        if self.tx.send(ClipCommand::Ping(ack)).is_ok() {
            let _ = done.recv();
        }
    }

    #[cfg(test)]
    fn set(&self, text: String) {
        let _ = self.tx.send(ClipCommand::Set(text));
    }

    #[cfg(test)]
    fn clear_if_unchanged(&self, text: String) {
        let _ = self.tx.send(ClipCommand::ClearIfUnchanged(text));
    }
}

#[cfg(test)]
struct MemoryBackend {
    store: std::sync::Arc<std::sync::Mutex<Option<String>>>,
}

#[cfg(test)]
impl ClipboardBackend for MemoryBackend {
    fn set_text(&mut self, text: String) {
        *self.store.lock().unwrap() = Some(text);
    }
    fn get_text(&mut self) -> Option<String> {
        self.store.lock().unwrap().clone()
    }
}

/// Observes the in-memory clipboard used in tests.
#[cfg(test)]
pub(crate) struct ClipboardProbe {
    store: std::sync::Arc<std::sync::Mutex<Option<String>>>,
    cleared: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

#[cfg(test)]
impl ClipboardProbe {
    pub(crate) fn current(&self) -> Option<String> {
        self.store.lock().unwrap().clone()
    }
    pub(crate) fn cleared_count(&self) -> usize {
        self.cleared.load(std::sync::atomic::Ordering::SeqCst)
    }
    pub(crate) fn set_external(&self, text: String) {
        *self.store.lock().unwrap() = Some(text);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The core ownership-drop regression guard: the value is still held by the
    // long-lived owner *after* copy() returns. A per-op clipboard (the old bug)
    // would have dropped it.
    #[test]
    fn owner_serves_value_after_copy_returns() {
        let (mgr, probe) = ClipboardManager::memory();
        mgr.copy("s3cret".into(), 0); // 0 = no auto-clear timer
        mgr.sync();
        assert_eq!(probe.current().as_deref(), Some("s3cret"));
        assert_eq!(probe.cleared_count(), 0);
    }

    #[test]
    fn clear_wipes_only_when_value_is_unchanged() {
        let (mgr, probe) = ClipboardManager::memory();
        mgr.set("A".into());
        mgr.clear_if_unchanged("A".into());
        mgr.sync();
        assert_eq!(probe.current().as_deref(), Some("")); // wiped
        assert_eq!(probe.cleared_count(), 1);
    }

    #[test]
    fn clear_is_skipped_when_clipboard_changed() {
        let (mgr, probe) = ClipboardManager::memory();
        mgr.set("A".into());
        mgr.set("B".into()); // replaced by user / another app
        mgr.clear_if_unchanged("A".into()); // stale auto-clear request
        mgr.sync();
        assert_eq!(probe.current().as_deref(), Some("B")); // left untouched
        assert_eq!(probe.cleared_count(), 0);
    }

    #[test]
    fn clear_on_lock_wipes_clipboard_if_holding_copied_value() {
        let (mgr, probe) = ClipboardManager::memory();
        mgr.copy("secret-pw".into(), 60);
        mgr.sync();
        assert_eq!(probe.current().as_deref(), Some("secret-pw"));

        mgr.clear_on_lock();
        mgr.sync();
        assert_eq!(probe.current().as_deref(), Some(""));
        assert_eq!(probe.cleared_count(), 1);
    }

    #[test]
    fn clear_on_lock_ignores_if_clipboard_overwritten_externally() {
        let (mgr, probe) = ClipboardManager::memory();
        mgr.copy("secret-pw".into(), 60);
        mgr.sync();

        // User copied something else in another application directly to OS clipboard
        probe.set_external("third-party-note".into());

        mgr.clear_on_lock();
        mgr.sync();
        assert_eq!(probe.current().as_deref(), Some("third-party-note"));
        assert_eq!(probe.cleared_count(), 0);
    }

    #[test]
    fn clear_on_lock_is_noop_if_nothing_copied() {
        let (mgr, probe) = ClipboardManager::memory();
        mgr.clear_on_lock();
        mgr.sync();
        assert_eq!(probe.current(), None);
        assert_eq!(probe.cleared_count(), 0);
    }

    #[test]
    fn clear_on_lock_is_noop_if_already_cleared_by_timer() {
        let (mgr, probe) = ClipboardManager::memory();
        mgr.set("secret-pw".into());
        mgr.clear_if_unchanged("secret-pw".into());
        mgr.sync();
        assert_eq!(probe.current().as_deref(), Some(""));
        assert_eq!(probe.cleared_count(), 1);

        mgr.clear_on_lock();
        mgr.sync();
        assert_eq!(probe.cleared_count(), 1);
    }

    // Exercises the real OS clipboard. Ignored by default: it clobbers the
    // developer's clipboard and needs a display server on Linux. Run on a
    // desktop with: cargo test -p vault-desktop -- --ignored
    #[test]
    #[ignore = "uses the real OS clipboard"]
    fn real_clipboard_round_trips() {
        let mut cb = arboard::Clipboard::new().unwrap();
        cb.set_text("vault-smoke".to_string()).unwrap();
        assert_eq!(cb.get_text().unwrap(), "vault-smoke");
    }
}
