// Hide the extra console window on Windows release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![forbid(unsafe_code)]

mod agent;
mod backups;
mod biometric;
mod bookmarks;
mod bridge;
mod clipboard;
mod commands;
mod conflicts;
mod keyfile_unlock;
#[cfg(target_os = "macos")]
mod protected_unlock;
mod reauth;
mod related_origins;
mod state;
mod sync;

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use tauri::{AppHandle, Emitter, Manager, WindowEvent};
use vault_store::VaultStore;

use clipboard::ClipboardManager;
use state::AppState;

/// OS keychain namespace for the device (quick-unlock) key.
const KEYCHAIN_SERVICE: &str = "no.sybr.vault";
const KEYCHAIN_ACCOUNT: &str = "default-vault";

/// The App Group shared with the macOS AutoFill extension.
#[cfg(target_os = "macos")]
pub(crate) const APP_GROUP: &str = "group.no.sybr.vault";

/// Last-modified time, or `None` when the file is missing/unreadable.
#[cfg(target_os = "macos")]
fn modified_at(path: &Path) -> Option<std::time::SystemTime> {
    std::fs::metadata(path).ok()?.modified().ok()
}

/// Resolve where the vault file lives: always the app-data directory.
///
/// The vault briefly lived in the shared App Group container so the macOS
/// AutoFill extension could read it. That extension is shelved, and the
/// container is a liability without it: reaching it at all requires a
/// provisioned entitlement, so if the profile lapses or the app is re-signed
/// without one, `container_path` returns `None` — and the app would silently
/// open a STALE app-data copy while the user keeps adding entries to it. A
/// password manager must never quietly serve the wrong vault.
///
/// So the app-data path is canonical, and a *newer* container copy is migrated
/// back down once (snapshotting whatever it replaces). The container copy is
/// left in place as an extra off-path backup.
fn resolve_vault_path(app: &tauri::App, data_dir: &Path) -> PathBuf {
    let app_data_vault = data_dir.join("default.vault");
    #[cfg(target_os = "macos")]
    {
        // The container path MUST come from Foundation's containerURL API: it is
        // that call which grants this (non-sandboxed but entitled) process access
        // to the container. A hardcoded path is denied with EPERM.
        if let Some(container) = vault_appgroup::container_path(APP_GROUP) {
            let shared_vault = container.join("default.vault");
            let shared_is_newer = match (modified_at(&shared_vault), modified_at(&app_data_vault)) {
                (Some(shared), Some(local)) => shared > local,
                (Some(_), None) => true, // only the container has a vault
                _ => false,
            };
            if shared_is_newer {
                // Never overwrite without a rollback point.
                let _ = vault_store::snapshot::capture(&app_data_vault);
                match std::fs::copy(&shared_vault, &app_data_vault) {
                    Ok(_) => {
                        let shared_settings = container.join("settings.json");
                        if shared_settings.exists() {
                            let _ = std::fs::copy(&shared_settings, data_dir.join("settings.json"));
                        }
                        eprintln!("[arca] migrated the newer App Group vault back to app data");
                    }
                    Err(e) => eprintln!(
                        "[arca] could not migrate the App Group vault back ({e}); \
                         using the app-data vault"
                    ),
                }
            }
        }
    }
    let _ = app; // unused on non-macOS
    app_data_vault
}

fn main() {
    #[cfg(target_os = "linux")]
    std::env::set_var("WEBKIT_DISABLE_DMABUF_RENDERER", "1");

    if std::env::args().any(|arg| arg == "--build-info") {
        println!(
            "{}",
            serde_json::json!({
                "version": env!("CARGO_PKG_VERSION"), "build": env!("ARCA_BUILD"),
                "commit": env!("ARCA_COMMIT"),
            })
        );
        return;
    }
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _, _| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.unminimize();
                let _ = window.show();
                let _ = window.set_focus();
            }
        }))
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        // Updates are checked and installed from the UI only, never
        // automatically: installing restarts the app, which drops an unlocked
        // vault and any half-finished edit.
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        .setup(|app| {
            // Resolve a per-user data directory for the single vault file.
            let data_dir = app.path().app_data_dir()?;
            std::fs::create_dir_all(&data_dir).ok();
            // On macOS this is the shared App Group container (migrated with a
            // backup); elsewhere the app-data dir.
            let vault_path = resolve_vault_path(app, &data_dir);

            // One build shipped the AutoFill device key under the SAME
            // service+account as the app's own login-keychain key, and the
            // app's unlock started resolving to it: four Touch ID prompts and
            // a master-password fallback every time. Machines that ran that
            // build heal themselves here.
            #[cfg(target_os = "macos")]
            let _ = vault_sharedkey::purge_legacy();

            let store = VaultStore::new(vault_path, KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT);
            // The sandboxed AutoFill extension can only read the App Group
            // container, so every save is mirrored there. Set on the store
            // rather than at the save sites: a cloud-sync merge saved without
            // touching the mirror once, and AutoFill spent the afternoon
            // filling the password from before the merge.
            #[cfg(target_os = "macos")]
            let store = match vault_appgroup::container_path(APP_GROUP) {
                Some(container) => store.with_mirror(container.join("default.vault")),
                None => store,
            };
            // Eagerly load the locked vault if a file already exists.
            let vault = if store.exists() {
                store.load().ok()
            } else {
                None
            };

            // Long-lived clipboard owner thread (keeps the secret pasteable on
            // Linux and auto-clears it on all platforms).
            let clipboard = ClipboardManager::spawn(app.handle().clone());

            let mut app_state = AppState::new(store, vault, clipboard);
            // Restore persisted (non-secret) settings, if any.
            app_state.settings = state::load_settings(app_state.store.path());
            app.manage(Mutex::new(app_state));
            // Shared map of in-flight autofill-consent prompts (used only when
            // the confirm-autofill setting is on).
            app.manage(bridge::PendingConsents::default());
            app.manage(bridge::PendingVerifications::default());
            app.manage(bridge::PendingPasskeyChoices::default());
            // Google Drive sync: background pull-merge-push loop. State lives in
            // the engine (vault-sync), not in Tauri's managed map.
            sync::start_loop(app.handle().clone());

            // Local autofill bridge for the browser extension (loopback + token;
            // gated on unlock + origin match). Best-effort: failure to bind just
            // means autofill is unavailable this session.
            if let Err(e) = bridge::start(app.handle().clone(), &data_dir) {
                eprintln!("autofill bridge unavailable: {e}");
            }

            // ssh-agent: expose vault SSH keys to ssh/git (Unix socket).
            agent::start(app.handle().clone());

            let backup_service = {
                let state = app.state::<Mutex<AppState>>();
                let state = state.lock().map_err(|_| "Vault state unavailable")?;
                backups::Backups::load(state.store.path())
            };
            app.manage(Mutex::new(backup_service));
            backups::start(app.handle().clone());

            // Background idle-timeout auto-lock.
            let handle = app.handle().clone();
            std::thread::spawn(move || idle_watcher(handle));
            // USB key file: lock on removal, unlock on insertion.
            {
                let handle = app.handle().clone();
                std::thread::spawn(move || keyfile_unlock::watch(handle));
            }
            #[cfg(target_os = "macos")]
            {
                let handle = app.handle().clone();
                std::thread::spawn(move || autofill_importer(handle));
            }

            // Tray icon (top bar on GNOME via AppIndicator, system tray
            // elsewhere). Menu-only on purpose: a password manager's tray
            // must never *reveal* anything, so the items are the three verbs
            // that need no window — open, lock, quit. Lock from here behaves
            // exactly like the idle/blur locks: same state change, same
            // "vault-locked" event, so the webview swaps to the lock screen
            // even if the window is up. Best-effort: on desktops with no
            // StatusNotifier host the app simply has no tray, not no launch.
            {
                use tauri::menu::{Menu, MenuItem};
                use tauri::tray::TrayIconBuilder;
                let open_i = MenuItem::with_id(app, "open", "Open Arca", true, None::<&str>)?;
                let lock_i = MenuItem::with_id(app, "lock", "Lock Vault", true, None::<&str>)?;
                let quit_i = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
                let menu = Menu::with_items(app, &[&open_i, &lock_i, &quit_i])?;
                let tray = TrayIconBuilder::with_id("main")
                    .menu(&menu)
                    .tooltip("Arca")
                    .on_menu_event(|app, event| match event.id.as_ref() {
                        "open" => {
                            if let Some(w) = app.get_webview_window("main") {
                                let _ = w.show();
                                let _ = w.unminimize();
                                let _ = w.set_focus();
                            }
                        }
                        "lock" => {
                            let mut locked = false;
                            if let Some(state) = app.try_state::<Mutex<AppState>>() {
                                if let Ok(mut st) = state.lock() {
                                    locked = st.lock().is_ok();
                                }
                            }
                            if locked {
                                let _ = app.emit("vault-locked", "tray");
                            }
                        }
                        "quit" => app.exit(0),
                        _ => {}
                    });
                let tray = match app.default_window_icon() {
                    Some(icon) => tray.icon(icon.clone()),
                    None => tray,
                };
                if let Err(e) = tray.build(app) {
                    eprintln!("tray unavailable: {e}");
                }
            }

            Ok(())
        })
        .on_window_event(|window, event| {
            // Auto-lock when the window loses focus (if enabled).
            if let WindowEvent::Focused(false) = event {
                let app = window.app_handle();
                if let Some(state) = app.try_state::<Mutex<AppState>>() {
                    if let Ok(mut st) = state.lock() {
                        // Don't lock when our own native dialog (e.g. the import
                        // file picker) stole focus — the user hasn't left the app.
                        let lock_on_blur = st.settings.lock_on_blur && !st.blur_lock_suppressed();
                        let mut locked = false;
                        if lock_on_blur && st.vault.as_ref().is_some_and(|v| v.is_unlocked()) {
                            locked = st.lock().is_ok();
                        }
                        if locked {
                            let _ = app.emit("vault-locked", "blur");
                        }
                    }
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            conflicts::compare_sync_conflict,
            conflicts::reveal_conflict_field,
            conflicts::resolve_sync_conflict,
            conflicts::keep_sync_conflict_copy,
            commands::vault_status,
            commands::app_info,
            commands::password_history,
            commands::copy_password_history,
            commands::restore_password_history,
            commands::verify_vault_backup,
            backups::backup_status,
            backups::configure_backups,
            backups::run_backup_now,
            commands::create_vault,
            commands::unlock,
            commands::quick_unlock,
            commands::enable_quick_unlock,
            commands::disable_quick_unlock,
            keyfile_unlock::keyfile_candidates,
            keyfile_unlock::keyfile_enroll,
            keyfile_unlock::keyfile_revoke,
            keyfile_unlock::keyfile_configure,
            keyfile_unlock::keyfile_unlock,
            commands::change_master_password,
            commands::sync_connect,
            commands::sync_disconnect,
            commands::sync_status,
            commands::sync_now,
            commands::sync_bootstrap,
            commands::merge_duplicates,
            commands::list_snapshots,
            commands::restore_snapshot,
            commands::export_vault_backup,
            commands::restore_vault_backup,
            commands::resolve_autofill_consent,
            commands::resolve_passkey_choice,
            commands::verify_passkey_approval,
            commands::cancel_passkey_verification,
            commands::confirm_passkey_approval,
            commands::lock,
            commands::touch,
            commands::list_items,
            commands::search_items,
            commands::get_item,
            commands::reveal_field,
            commands::copy_field,
            commands::copy_to_clipboard,
            commands::upsert_item,
            commands::upsert_wifi,
            commands::upsert_secure_note,
            commands::upsert_bookmark,
            commands::move_bookmarks,
            commands::list_bookmark_sources,
            commands::import_bookmarks,
            commands::wifi_qr,
            commands::generate_ssh_key,
            commands::ssh_public_key,
            commands::ssh_agent_info,
            commands::delete_item,
            commands::restore_item,
            commands::purge_item,
            commands::current_totp,
            commands::security_report,
            commands::check_breaches,
            commands::import_logins,
            commands::export_logins_csv,
            commands::open_passwords_app,
            commands::generate,
            commands::get_settings,
            commands::set_settings,
            commands::set_blur_lock_suppressed,
        ])
        .build(tauri::generate_context!())
        .expect("error while running the Arca application")
        .run(|app, event| {
            // The bridge's port dies with the process; the file naming it does
            // not. Remove it on the way out so nothing keeps pointing at a port
            // Arca no longer owns.
            if matches!(event, tauri::RunEvent::Exit) {
                if let Ok(dir) = app.path().app_data_dir() {
                    bridge::stop(&dir);
                }
            }
        });
}

/// Polls once per second; locks the vault after the configured idle timeout.
fn idle_watcher(app: AppHandle) {
    loop {
        std::thread::sleep(Duration::from_secs(1));
        let state = app.state::<Mutex<AppState>>();
        let mut locked = false;
        if let Ok(mut st) = state.lock() {
            let timeout = st.settings.auto_lock_secs;
            if timeout > 0 {
                let idle = st.last_activity.elapsed();
                if idle >= Duration::from_secs(timeout)
                    && st.vault.as_ref().is_some_and(|v| v.is_unlocked())
                {
                    locked = st.lock().is_ok();
                }
            }
        }
        if locked {
            let _ = app.emit("vault-locked", "idle");
        }
    }
}

/// The extension can save while the desktop is locked or closed. Its encrypted
/// inbox survives both; import only into an authenticated desktop session.
#[cfg(target_os = "macos")]
fn autofill_importer(app: AppHandle) {
    loop {
        std::thread::sleep(Duration::from_secs(3));
        let imported = {
            let state = app.state::<Mutex<AppState>>();
            let Ok(mut st) = state.lock() else { continue };
            let AppState { store, vault, .. } = &mut *st;
            let Some(vault) = vault.as_mut().filter(|vault| vault.is_unlocked()) else {
                continue;
            };
            match store.import_autofill_registrations(vault) {
                Ok(count) => count > 0,
                Err(_) => {
                    eprintln!(
                        "[arca] AutoFill registration import deferred; encrypted inbox retained"
                    );
                    false
                }
            }
        };
        if imported {
            sync::mark_dirty();
            commands::publish_identities(&app);
            let _ = app.emit("vault-unlocked", ());
        }
    }
}
