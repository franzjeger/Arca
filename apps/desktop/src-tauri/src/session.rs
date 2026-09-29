//! What follows the vault opening, whichever way it opened.

use tauri::{AppHandle, Emitter};

/// Everything that follows an unlock: the window, the OS AutoFill store and
/// sync all hear about it. The master password, Touch ID or Windows Hello, a
/// USB key and a browser request each used to run their own subset of this,
/// so a vault opened from the browser refreshed neither AutoFill nor sync.
/// Locking has its single path in `AppState::lock`.
pub fn unlocked(app: &AppHandle) {
    let _ = app.emit("vault-unlocked", ());
    crate::commands::publish_identities(app);
    crate::commands::kick_sync(app);
}
