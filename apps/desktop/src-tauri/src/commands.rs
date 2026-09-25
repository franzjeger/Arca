//! Tauri commands bridging the webview UI to `vault-core`/`vault-store`.
//!
//! Each `#[tauri::command]` is a thin wrapper that resolves the managed state
//! and delegates to a `do_*` function taking `&Mutex<AppState>`. The `do_*`
//! functions hold the real logic and are unit-tested directly (see the bottom
//! of this file) without needing a Tauri runtime.
//!
//! Secret-exposure policy:
//!   * `get_item` returns metadata + non-secret fields (title/username/url),
//!     never the password or TOTP secret.
//!   * Secrets cross to the UI only on explicit user action: `reveal_field`
//!     (to display) or `current_totp` (a short-lived code).
//!   * `copy_field` copies a secret to the OS clipboard via the clipboard owner
//!     thread, so the plaintext never enters the webview, and auto-clears.
//!   * Nothing here logs secrets.

use std::sync::Mutex;
#[cfg(target_os = "macos")]
use tauri::Manager;

use serde::{Deserialize, Serialize};
use tauri::{Emitter, State};
use uuid::Uuid;

use vault_core::{
    estimate_strength, generate_password, Item, ItemKind, KdfParams, PasswordOptions,
    PasswordStrength, SecurityIssue, Vault, VaultItem,
};

use crate::state::{now_millis, now_secs, AppState, CmdError, Settings};

// ---- DTOs (camelCase for the TS frontend) ---------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultStatus {
    /// A vault file exists (or one is loaded in memory).
    pub exists: bool,
    pub unlocked: bool,
    /// Quick-unlock material is present in the vault header.
    pub has_quick_unlock: bool,
    /// A device key is available in the OS keychain right now.
    pub quick_unlock_available: bool,
    /// Biometric (Touch ID) authentication is wired on this platform, so quick
    /// unlock can be gated behind it.
    pub biometric_available: bool,
    pub quick_unlock_protected: bool,
    /// A USB key file is enrolled for this vault (Linux). `None` otherwise.
    pub key_file: Option<crate::keyfile_unlock::KeyFileStatus>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemSummaryDto {
    pub is_sync_conflict: bool,
    pub conflict_of: Option<String>,
    pub id: String,
    pub kind: String,
    pub title: String,
    pub subtitle: String,
    /// First letter of the title, for the colored list tile.
    pub letter: String,
    /// Normalized website host ("github.com"; empty when the item has no URL),
    /// using the same normalization as autofill matching. The list groups
    /// entries that share a host.
    pub host: String,
    /// Bookmark folder path, `/`-separated; empty for every other kind.
    pub folder: String,
    pub has_totp: bool,
    pub is_deleted: bool,
    pub modified_at: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemDetailDto {
    pub id: String,
    pub kind: String,
    pub title: String,
    pub username: String,
    pub url: String,
    pub notes: String,
    /// Whether a password is set (the value itself is fetched on demand).
    pub has_password: bool,
    pub has_totp: bool,
    /// Coarse strength bucket of the stored password: "weak" | "fair" | "strong"
    /// (None when there is no password). Derived metadata, not the secret.
    pub password_strength: Option<String>,
    pub is_deleted: bool,
    pub created_at: i64,
    pub modified_at: i64,
    // ---- Wi-Fi fields (empty/false for other kinds) ----
    /// Network name.
    pub ssid: String,
    /// Auth token: "WPA" | "WEP" | "nopass".
    pub security: String,
    /// Hidden SSID.
    pub hidden: bool,
    // ---- Bookmark fields (empty for other kinds) ----
    /// Folder path, `/`-separated. Empty means the top of the bar.
    pub folder: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityIssueDto {
    pub id: String,
    /// Issue tags: "weak" and/or "reused".
    pub issues: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportSummary {
    /// Logins added to the vault.
    pub imported: usize,
    /// Existing logins (same site + username) whose password changed and was
    /// updated in place.
    pub updated: usize,
    /// Rows identical to an existing login (same site + username + password),
    /// skipped so re-importing an export never creates copies.
    pub duplicates: usize,
    /// Rows skipped (blank, or no username and no password).
    pub skipped: usize,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginInput {
    /// `None` to create a new item, `Some(id)` to update an existing one.
    pub id: Option<String>,
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub totp_secret: Option<String>,
    pub notes: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TotpDto {
    pub code: String,
    pub period: u64,
    pub remaining: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordOptionsDto {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
}

// ---- helpers --------------------------------------------------------------

type St<'a> = State<'a, Mutex<AppState>>;

pub(crate) fn guard(
    state: &Mutex<AppState>,
) -> Result<std::sync::MutexGuard<'_, AppState>, CmdError> {
    state
        .lock()
        .map_err(|_| CmdError::new("poisoned", "Internal state error."))
}

fn kind_str(kind: ItemKind) -> &'static str {
    match kind {
        ItemKind::Login => "login",
        ItemKind::Passkey => "passkey",
        ItemKind::SshKey => "sshKey",
        ItemKind::Wifi => "wifi",
        ItemKind::SecureNote => "secureNote",
        ItemKind::Bookmark => "bookmark",
        ItemKind::Unknown => "unknown",
    }
}

fn strength_str(s: PasswordStrength) -> &'static str {
    match s {
        PasswordStrength::Weak => "weak",
        PasswordStrength::Fair => "fair",
        PasswordStrength::Strong => "strong",
    }
}

fn issue_str(issue: SecurityIssue) -> &'static str {
    match issue {
        SecurityIssue::WeakPassword => "weak",
        SecurityIssue::ReusedPassword => "reused",
    }
}

fn parse_id(s: &str) -> Result<Uuid, CmdError> {
    Uuid::parse_str(s).map_err(|_| CmdError::new("not_found", "Invalid item id."))
}

/// Refuse to route an existing item through an editor for another item type.
///
/// The frontend is not a security boundary: a stale UI, browser devtools, or a
/// future wiring mistake can invoke any Tauri command directly. Without this
/// check, `upsert_item(id_of_a_passkey, ...)` replaces the passkey payload with
/// a login and irreversibly discards its private key.
fn require_kind(item: &Item, expected: ItemKind) -> Result<(), CmdError> {
    if item.data.kind() == expected {
        Ok(())
    } else {
        Err(CmdError::new(
            "item_kind_mismatch",
            "This editor cannot change the item's type.",
        ))
    }
}

fn first_letter(title: &str) -> String {
    title
        .chars()
        .find(|c| c.is_alphanumeric())
        .map(|c| c.to_uppercase().to_string())
        .unwrap_or_else(|| "#".to_string())
}

fn normalize_bookmark_folder(folder: &str) -> String {
    folder
        .split('/')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("/")
}

fn contains_query(value: &str, query: &str) -> bool {
    value.to_lowercase().contains(query)
}

/// Search decrypted fields in Rust and return ids only. In particular this
/// lets notes participate in search without copying every note into the
/// webview's long-lived item list.
fn item_matches_query(item: &VaultItem, query: &str) -> bool {
    let matches = |fields: &[&str]| fields.iter().any(|value| contains_query(value, query));
    match item {
        VaultItem::Login {
            title,
            username,
            url,
            notes,
            ..
        } => matches(&[title, username, url, notes]),
        VaultItem::Passkey {
            title,
            rp_id,
            user_name,
            ..
        } => matches(&[title, rp_id, user_name]),
        VaultItem::SshKey {
            title,
            comment,
            key_type,
            fingerprint,
            ..
        } => matches(&[title, comment, key_type, fingerprint]),
        VaultItem::Wifi {
            title, ssid, notes, ..
        } => matches(&[title, ssid, notes]),
        VaultItem::SecureNote { title, body } => matches(&[title, body]),
        VaultItem::Bookmark {
            title,
            url,
            folder,
            notes,
        } => matches(&[title, url, folder, notes]),
        VaultItem::Unknown(unknown) => contains_query(&unknown.kind, query),
    }
}

/// Persist the current vault to disk (atomic write). Sync-aware: if a synced
/// peer rewrote the file, its changes are merged in first so they aren't
/// clobbered (see [`vault_store::VaultStore::save_synced`]).
fn save_state(st: &mut AppState) -> Result<(), CmdError> {
    let AppState { store, vault, .. } = st;
    let vault = vault
        .as_mut()
        .ok_or_else(|| CmdError::new("no_vault", "No vault is loaded."))?;
    store.save_synced(vault)?;
    // Local state changed: let the cloud-sync loop know there is work.
    crate::sync::mark_dirty();
    Ok(())
}

/// Hold the complete pre-edit state until the write commits. Restoring the
/// clone also restores revision ancestry, purges and header changes exactly.
pub(crate) struct WriteGuard<'a> {
    state: std::sync::MutexGuard<'a, AppState>,
    previous: Option<Vault>,
    committed: bool,
}

impl std::ops::Deref for WriteGuard<'_> {
    type Target = AppState;
    fn deref(&self) -> &AppState {
        &self.state
    }
}

impl std::ops::DerefMut for WriteGuard<'_> {
    fn deref_mut(&mut self) -> &mut AppState {
        &mut self.state
    }
}

impl Drop for WriteGuard<'_> {
    fn drop(&mut self) {
        if !self.committed {
            self.state.vault = self.previous.take();
        }
    }
}

pub(crate) fn write_guard(state: &Mutex<AppState>) -> Result<WriteGuard<'_>, CmdError> {
    let state = guard(state)?;
    let previous = state.vault.clone();
    Ok(WriteGuard {
        state,
        previous,
        committed: false,
    })
}

pub(crate) fn persist(st: &mut WriteGuard<'_>) -> Result<(), CmdError> {
    save_state(st)?;
    st.committed = true;
    Ok(())
}

/// Accept either a raw Base32 secret or a full `otpauth://` URI for the TOTP
/// field, normalizing to the stored Base32 secret. Empty input -> `None`.
fn normalize_totp_secret(raw: Option<String>) -> Result<Option<String>, CmdError> {
    match raw {
        Some(s) if !s.trim().is_empty() => {
            let s = s.trim();
            if s.to_ascii_lowercase().starts_with("otpauth://") {
                Ok(Some(vault_core::parse_otpauth_uri(s)?.secret))
            } else {
                Ok(Some(s.to_string()))
            }
        }
        _ => Ok(None),
    }
}

/// A login parsed from one CSV row. `totp` is raw (Base32 or `otpauth://`),
/// normalized later via [`normalize_totp_secret`].
struct ParsedLogin {
    title: String,
    username: String,
    password: String,
    url: String,
    totp: String,
    notes: String,
}

/// Column indices discovered from the CSV header.
#[derive(Default)]
struct ColumnMap {
    title: Option<usize>,
    url: Option<usize>,
    username: Option<usize>,
    password: Option<usize>,
    totp: Option<usize>,
    notes: Option<usize>,
}

/// Derive a title when the export has none: site host, else username, else a
/// generic label.
fn title_from(url: &str, username: &str) -> String {
    let host = url
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or("")
        .trim();
    if !host.is_empty() {
        host.to_string()
    } else if !username.is_empty() {
        username.to_string()
    } else {
        "Imported".to_string()
    }
}

/// Parse a password-export CSV (Chrome/Brave/Edge, Apple Passwords, Firefox, and
/// common generic layouts) by mapping header names case-insensitively. Returns
/// the parsed logins plus the count of skipped (blank / credential-less) rows.
fn parse_logins_csv(text: &str) -> (Vec<ParsedLogin>, usize) {
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(true)
        .flexible(true)
        .from_reader(text.as_bytes());

    let headers = match reader.headers() {
        Ok(h) => h.clone(),
        Err(_) => return (Vec::new(), 0),
    };

    let mut map = ColumnMap::default();
    for (i, h) in headers.iter().enumerate() {
        match h.trim().to_ascii_lowercase().as_str() {
            "title" | "name" => _ = map.title.get_or_insert(i),
            "url" | "urls" | "website" | "login_uri" | "loginuri" => _ = map.url.get_or_insert(i),
            "username" | "user" | "login" | "email" | "login_username" => {
                _ = map.username.get_or_insert(i)
            }
            "password" | "pwd" | "login_password" => _ = map.password.get_or_insert(i),
            "notes" | "note" | "comment" | "comments" => _ = map.notes.get_or_insert(i),
            "otpauth" | "otp" | "totp" | "otp_auth" | "totpauth" | "2fa" => {
                _ = map.totp.get_or_insert(i)
            }
            _ => {}
        }
    }

    let mut logins = Vec::new();
    let mut skipped = 0usize;
    for record in reader.records().flatten() {
        let cell = |col: Option<usize>| -> String {
            col.and_then(|i| record.get(i))
                .unwrap_or("")
                .trim()
                .to_string()
        };
        let username = cell(map.username);
        let password = cell(map.password);
        if username.is_empty() && password.is_empty() {
            skipped += 1;
            continue;
        }
        let url = cell(map.url);
        let mut title = cell(map.title);
        if title.is_empty() {
            title = title_from(&url, &username);
        }
        logins.push(ParsedLogin {
            title,
            username,
            password,
            url,
            totp: cell(map.totp),
            notes: cell(map.notes),
        });
    }
    (logins, skipped)
}

fn secret_field(item: &Item, field: &str) -> Result<String, CmdError> {
    match (&item.data, field) {
        (VaultItem::Login { password, .. }, "password") => Ok(password.clone()),
        (VaultItem::Login { totp_secret, .. }, "totp_secret") => {
            Ok(totp_secret.clone().unwrap_or_default())
        }
        (VaultItem::Login { notes, .. }, "notes") => Ok(notes.clone()),
        (VaultItem::Wifi { password, .. }, "password") => Ok(password.clone()),
        (VaultItem::Wifi { notes, .. }, "notes") => Ok(notes.clone()),
        (VaultItem::SecureNote { body, .. }, "notes") => Ok(body.clone()),
        _ => Err(CmdError::new(
            "invalid_field",
            "Unknown or unavailable field.",
        )),
    }
}

// ---- lifecycle commands ---------------------------------------------------

#[tauri::command]
pub fn vault_status(state: St<'_>) -> Result<VaultStatus, CmdError> {
    let st = guard(state.inner())?;
    Ok(VaultStatus {
        exists: st.store.exists() || st.vault.is_some(),
        unlocked: st.vault.as_ref().map(Vault::is_unlocked).unwrap_or(false),
        has_quick_unlock: st
            .vault
            .as_ref()
            .map(Vault::has_device_unlock)
            .unwrap_or(false),
        quick_unlock_available: {
            #[cfg(target_os = "macos")]
            {
                crate::protected_unlock::available(&st.store)
            }
            #[cfg(not(target_os = "macos"))]
            {
                st.store.quick_unlock_available()
            }
        },
        key_file: crate::keyfile_unlock::status(&st.store),
        quick_unlock_protected: {
            #[cfg(target_os = "macos")]
            {
                crate::protected_unlock::fully_protected(&st.store)
            }
            #[cfg(not(target_os = "macos"))]
            {
                false
            }
        },
        biometric_available: crate::biometric::available(),
    })
}

#[tauri::command]
pub fn create_vault(state: St<'_>, master_password: String) -> Result<(), CmdError> {
    do_create_vault(state.inner(), &master_password)
}

fn do_create_vault(state: &Mutex<AppState>, master_password: &str) -> Result<(), CmdError> {
    if master_password.chars().count() < 8 {
        return Err(CmdError::new(
            "weak_password",
            "Use at least 8 characters for the master password.",
        ));
    }
    let mut st = write_guard(state)?;
    if st.store.exists() {
        return Err(CmdError::new("exists", "A vault already exists."));
    }
    let params = KdfParams::new_default().map_err(CmdError::from)?;
    let vault = Vault::create(master_password, params)?;
    st.vault = Some(vault);
    persist(&mut st)?;
    st.touch();
    Ok(())
}

/// Publish the vault's logins and passkeys to the OS AutoFill store.
///
/// macOS only offers Arca for sites it has been told Arca holds something for.
/// Until this existed, the only thing that ever told it was a button in a
/// separate dev harness — so system AutoFill was as current as the last time
/// somebody remembered to press it, and the app people actually run published
/// nothing at all. iOS has always done this on unlock; this is the Mac catching
/// up.
///
/// METADATA ONLY, which is what makes it safe to leave published while the
/// vault is shut: a host, a username, a record id, and for passkeys the
/// credential id and user handle the relying party already knows. The extension
/// fetches the secret itself, one per fill, behind its own biometric.
///
/// On its own thread: the store call blocks, and nobody should wait behind it
/// to see their own vault.
pub(crate) fn publish_identities(app: &tauri::AppHandle) {
    use tauri::Manager;
    let app = app.clone();
    std::thread::spawn(move || {
        let (identities, mirror) = {
            let state = app.state::<Mutex<AppState>>();
            let Ok(st) = state.lock() else { return };
            let Some(vault) = st.vault.as_ref().filter(|v| v.is_unlocked()) else {
                return;
            };
            // Publishing without this is the failure that looks most like
            // success: the identities appear in Safari, and every one of them
            // fails to fill.
            let mirror = mirror_for_autofill(&st);
            let Ok(summaries) = vault.list_items(false) else {
                return;
            };
            let mut out = Vec::new();
            for s in summaries {
                let Ok(item) = vault.get_item(s.id) else {
                    continue;
                };
                match &item.data {
                    vault_core::VaultItem::Login { url, username, .. } => {
                        let host = crate::bridge::host_of(url);
                        if host.is_empty() {
                            continue;
                        }
                        out.push(vault_credstore::Identity::Password {
                            domain: host,
                            user: username.clone(),
                            record: item.id.to_string(),
                        });
                    }
                    vault_core::VaultItem::Passkey {
                        rp_id,
                        user_name,
                        credential_id,
                        user_handle,
                        ..
                    } => out.push(vault_credstore::Identity::Passkey {
                        rp_id: rp_id.clone(),
                        user: user_name.clone(),
                        credential_id: credential_id.clone(),
                        user_handle: user_handle.clone(),
                        record: item.id.to_string(),
                    }),
                    _ => {}
                }
            }
            (out, mirror)
        };
        let outcome = vault_credstore::replace(&identities);

        // Written down, not only emitted. The last time this answer existed
        // only as an event, nothing listened and the question "did it publish?"
        // had no way to be answered at all.
        if let Ok(st) = app.state::<Mutex<AppState>>().lock() {
            if let Some(dir) = st.store.path().parent() {
                use std::io::Write;
                let stamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                if let Ok(mut f) = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(dir.join("autofill-publish.log"))
                {
                    let _ = writeln!(
                        f,
                        "{stamp}\tcount={}\t{outcome}\t{mirror}",
                        identities.len()
                    );
                }
            }
        }
        // Told, not swallowed: "AutoFill is off for Arca" is a switch the user
        // can flip, and the store accepts a publish in that state and discards
        // it — so silence here would look exactly like success.
        let _ = app.emit(
            "autofill-published",
            serde_json::json!({
                "count": identities.len(),
                "ok": outcome == vault_credstore::Published::Ok,
                "message": outcome.to_string(),
            }),
        );
    });
}

/// Give the sandboxed AutoFill extension the two things it needs to serve what
/// [`publish_identities`] advertises: the vault bytes, and the key that opens
/// them.
///
/// The extension is sandboxed, so it can reach exactly one vault file (the App
/// Group container) and exactly one keychain (data-protection, shared access
/// group). The app uses neither: it keeps the canonical vault in app data and
/// its own device key in the login keychain. `ArcaHost` used to bridge that gap
/// on unlock, and when that harness was deleted the bridge went with it —
/// leaving an extension that appeared in Safari, took a fingerprint, and then
/// failed with `noDeviceKey`, against a container copy that had stopped being
/// updated two weeks earlier.
///
/// Both halves are best-effort by design. A credential provider that cannot
/// start is an inconvenience; an app that will not unlock is a lockout.
#[cfg(target_os = "macos")]
fn mirror_for_autofill(st: &AppState) -> String {
    // The vault half is the store's job now (VaultStore::with_mirror), so it
    // cannot be skipped by a save path that forgot to ask. Report it here
    // anyway: this log line is where anyone debugging AutoFill looks first.
    // Saves keep the mirror current, but an unlock is not a save — and after a
    // cloud sync pulled a phone's edits down, "not a save" meant AutoFill kept
    // filling the password from before the merge.
    let vault_note = if st.store.refresh_mirror() {
        "vault mirrored"
    } else {
        "vault NOT mirrored (no App Group container?)"
    };

    // Publishing metadata must never read a protected secret or prompt again.
    // Enrollment and legacy quick unlock copy their already authenticated key.
    format!("{vault_note}; AutoFill key retained (no extra keychain read)")
}

#[cfg(not(target_os = "macos"))]
fn mirror_for_autofill(_st: &AppState) -> String {
    "not macOS".to_string()
}

/// Kick a background sync right away (used after unlock so peer changes land
/// immediately instead of waiting for the next 30s tick — while locked, the
/// background loop skips cycles by design).
pub(crate) fn kick_sync(app: &tauri::AppHandle) {
    let app = app.clone();
    std::thread::spawn(move || {
        let _ = crate::sync::sync_now(&app);
    });
}

#[tauri::command]
pub fn unlock(
    app: tauri::AppHandle,
    state: St<'_>,
    master_password: String,
) -> Result<(), CmdError> {
    do_unlock(state.inner(), &master_password)?;
    publish_identities(&app);
    kick_sync(&app);
    Ok(())
}

fn do_unlock(state: &Mutex<AppState>, master_password: &str) -> Result<(), CmdError> {
    let mut st = guard(state)?;
    st.unlock_generation = st.unlock_generation.wrapping_add(1);
    // Load the locked vault from disk if it isn't in memory yet.
    if st.vault.is_none() && st.store.exists() {
        st.vault = Some(st.store.load()?);
    }
    st.vault_mut()?.unlock(master_password)?;

    // macOS enrollment/repair is explicitly authenticated in Settings. Never
    // recreate a plain login-keychain key, even if the protected marker was lost.
    // Other platforms retain their existing password-unlock drift repair.
    let needs_heal = {
        let AppState { store, vault, .. } = &*st;
        !cfg!(target_os = "macos")
            && vault
                .as_ref()
                .map(|v| store.quick_unlock_stale(v))
                .unwrap_or(false)
    };
    if needs_heal {
        {
            let AppState { store, vault, .. } = &mut *st;
            if let Some(v) = vault.as_mut() {
                let _ = store.enable_quick_unlock(v);
            }
        }
        let _ = save_state(&mut st);
    }
    // A USB key whose sidecar no longer opens this vault (restored backup, a
    // vault adopted from a peer) is re-bound now that the password proved the
    // user. Its own file, no vault change.
    crate::keyfile_unlock::heal(&mut st);

    st.touch();
    Ok(())
}

/// Run the blocking biometric prompt on a WORKER thread, with the app handle
/// the Windows implementation needs for window parenting.
///
/// Sync commands run on the main thread, and the prompt blocks until the user
/// answers — so calling it inline froze Arca's message pump for the whole
/// dialog. On macOS that merely froze our window behind Touch ID's overlay; on
/// Windows the Hello dialog needs the app's pump ALIVE to paint and take
/// focus, so blocking it produced a PIN box that could not be typed into.
/// Every biometric-gated command is async and awaits this instead.
#[cfg(not(target_os = "macos"))]
async fn authenticate_off_main(
    app: tauri::AppHandle,
    reason: &'static str,
) -> Result<(), CmdError> {
    tauri::async_runtime::spawn_blocking(move || crate::biometric::authenticate(Some(&app), reason))
        .await
        .map_err(|_| CmdError::new("internal", "the verification task failed"))?
        .map_err(|m| CmdError::new("biometric_failed", &m))
}

/// Unlock using the OS keychain device key (no master password), gated behind a
/// biometric (Touch ID) prompt where available.
#[cfg(not(target_os = "macos"))]
#[tauri::command]
pub async fn quick_unlock(app: tauri::AppHandle, state: St<'_>) -> Result<(), CmdError> {
    // Prompt for Touch ID / Windows Hello *before* taking the state lock — the
    // prompt blocks on user interaction, and we must not freeze other commands
    // meanwhile. This app-layer biometric is the single gate on ALL platforms:
    // the device key is now a plain keychain item (reliably readable), so the
    // biometric is enforced here rather than by a per-item keychain access
    // control (that macOS variant broke unlock under dev signing — see
    // vault-store::keychain). No-op on platforms without a biometric provider.
    authenticate_off_main(app.clone(), "unlock your password vault").await?;

    let mut st = guard(state.inner())?;
    if st.vault.is_none() && st.store.exists() {
        st.vault = Some(st.store.load()?);
    }
    let AppState { store, vault, .. } = &mut *st;
    let vault = vault.as_mut().ok_or_else(CmdError::no_vault)?;
    if let Err(e) = store.quick_unlock(vault) {
        // The user just passed Touch ID; if the stored key no longer unwraps
        // the header (stale drift), say so explicitly — the frontend then stops
        // re-prompting and asks for the master password once, which repairs
        // quick unlock via the self-heal in `do_unlock`.
        if store.quick_unlock_stale(vault) {
            return Err(CmdError::new(
                "quick_unlock_stale",
                "Quick unlock is out of sync with this vault. Enter your master password once to repair it.",
            ));
        }
        return Err(e.into());
    }
    st.touch();
    drop(st);
    publish_identities(&app);
    kick_sync(&app);
    Ok(())
}

#[cfg(target_os = "macos")]
#[tauri::command]
pub async fn quick_unlock(app: tauri::AppHandle) -> Result<(), CmdError> {
    let worker = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let state = worker.state::<Mutex<AppState>>();
        crate::protected_unlock::unlock(state.inner(), Some(&worker))
    })
    .await
    .map_err(|_| CmdError::new("internal", "Unlock worker stopped."))??;
    let _ = app.emit("vault-unlocked", ());
    publish_identities(&app);
    kick_sync(&app);
    Ok(())
}

/// Deliver the user's Allow/Deny decision for a pending autofill-consent prompt
/// to the parked bridge thread (see `bridge::PendingConsents`).
#[tauri::command]
pub fn resolve_autofill_consent(app: tauri::AppHandle, id: String, approved: bool) {
    crate::bridge::resolve_consent(&app, &id, approved);
}

/// User verification for a pending passkey ceremony (Windows/Linux, where the OS
/// Hello dialog can't take input when invoked from our background bridge thread).
/// Checks the master password against the unlocked vault; on success, resolves
/// the parked bridge thread with `true` (UV satisfied). Returns whether the
/// password was correct so the dialog can show a retry hint — a wrong password
/// does NOT resolve/deny, letting the user retry until they cancel or it times
/// out. Cancelling reuses `resolve_autofill_consent(id, false)`.
#[tauri::command]
pub fn verify_passkey_approval(
    app: tauri::AppHandle,
    state: St<'_>,
    id: String,
    master_password: String,
) -> Result<bool, CmdError> {
    let ok = {
        let st = guard(state.inner())?;
        let vault = st.vault.as_ref().ok_or_else(CmdError::no_vault)?;
        if !vault.is_unlocked() {
            return Err(CmdError::new("locked", "Vault is locked"));
        }
        vault.verify_master_password(&master_password)
    };
    if ok {
        // Dedicated verification channel: only this password-checked path (or a
        // cancel, always `false`) can resolve it, so UV=1 can never be set by
        // the presence-only autofill-consent resolver.
        crate::bridge::resolve_verification(&app, &id, true);
    }
    Ok(ok)
}

#[cfg(target_os = "macos")]
#[tauri::command]
pub async fn enable_quick_unlock(app: tauri::AppHandle) -> Result<(), CmdError> {
    let worker = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let state = worker.state::<Mutex<AppState>>();
        crate::protected_unlock::enable(state.inner())
    })
    .await
    .map_err(|_| CmdError::new("internal", "Touch ID setup worker stopped."))??;
    publish_identities(&app);
    Ok(())
}

/// Cancel a pending passkey user-verification (the user dismissed the dialog).
/// Always resolves the parked ceremony as denied.
#[tauri::command]
pub fn cancel_passkey_verification(app: tauri::AppHandle, id: String) {
    crate::bridge::resolve_verification(&app, &id, false);
}

/// Approve a pending passkey ceremony with the dialog's single button — only
/// honoured when the bridge registered it as click-approvable (the default);
/// a password-required one stays parked and returns `false`.
#[tauri::command]
pub fn confirm_passkey_approval(app: tauri::AppHandle, id: String) -> bool {
    crate::bridge::confirm_verification(&app, &id)
}

#[cfg(not(target_os = "macos"))]
#[tauri::command]
pub fn enable_quick_unlock(state: St<'_>) -> Result<(), CmdError> {
    let mut st = write_guard(state.inner())?;
    {
        let AppState { store, vault, .. } = &mut *st;
        let vault = vault.as_mut().ok_or_else(CmdError::no_vault)?;
        store.enable_quick_unlock(vault)?;
    }
    persist(&mut st)?;
    // Share the brand-new key with the AutoFill extension NOW. It is otherwise
    // shared on unlock, and the user who just switched Touch ID on is already
    // unlocked — so AutoFill would keep failing until the next lock/unlock
    // cycle, which reads as "turning it on did nothing".
    let _ = mirror_for_autofill(&st);
    st.touch();
    Ok(())
}

/// Export all logins to a CSV file at `path`, re-importable by Arca (and by
/// generic password managers). Gated behind a biometric re-auth because it
/// writes EVERY password to a plaintext file. Rust writes the file directly, so
/// the plaintext never passes through the webview. Returns the row count.
#[tauri::command]
pub async fn export_logins_csv(
    app: tauri::AppHandle,
    state: St<'_>,
    path: String,
    current_password: Option<String>,
) -> Result<usize, CmdError> {
    let authorization =
        crate::reauth::authorize(&app, "export your passwords to a file", current_password).await?;
    let mut st = guard(state.inner())?;
    authorization.validate(&st)?;
    st.touch();
    let vault = st.vault.as_ref().ok_or_else(CmdError::no_vault)?;
    if !vault.is_unlocked() {
        return Err(CmdError::new("locked", "Unlock the vault first."));
    }
    let mut wtr = csv::Writer::from_path(&path)
        .map_err(|e| CmdError::new("export", &format!("Could not create the file: {e}")))?;
    wtr.write_record(["title", "url", "username", "password", "totp", "notes"])
        .map_err(|e| CmdError::new("export", &e.to_string()))?;
    let mut n = 0usize;
    if let Ok(summaries) = vault.list_items(false) {
        for s in summaries {
            let Ok(item) = vault.get_item(s.id) else {
                continue;
            };
            if let VaultItem::Login {
                title,
                url,
                username,
                password,
                totp_secret,
                notes,
            } = &item.data
            {
                wtr.write_record([
                    title.as_str(),
                    url.as_str(),
                    username.as_str(),
                    password.as_str(),
                    totp_secret.as_deref().unwrap_or(""),
                    notes.as_str(),
                ])
                .map_err(|e| CmdError::new("export", &e.to_string()))?;
                n += 1;
            }
        }
    }
    wtr.flush()
        .map_err(|e| CmdError::new("export", &e.to_string()))?;
    Ok(n)
}

// ---- backup & restore -----------------------------------------------------

/// One rotated local snapshot, for the restore list.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotSummary {
    /// Absolute path, passed back verbatim to `restore_snapshot`.
    pub path: String,
    /// Unix seconds the snapshot was taken.
    pub created_unix: i64,
    pub bytes: u64,
}

/// Local snapshots of the vault, newest first. Metadata only (they are
/// encrypted blobs), so this needs no unlock and reveals nothing.
#[tauri::command]
pub fn list_snapshots(state: St<'_>) -> Result<Vec<SnapshotSummary>, CmdError> {
    let st = guard(state.inner())?;
    Ok(st
        .store
        .snapshots()
        .into_iter()
        .map(|s| SnapshotSummary {
            path: s.path.to_string_lossy().into_owned(),
            created_unix: s.created_unix,
            bytes: s.bytes,
        })
        .collect())
}

/// Roll the vault back to a snapshot.
///
/// Destructive, so it is gated behind a biometric re-auth. The current state is
/// snapshotted first (the restore is itself undoable). The restored file may
/// predate a master-password change, so we drop the in-memory vault and leave
/// the app locked: the user unlocks with whatever password that snapshot used.
#[tauri::command]
pub async fn restore_snapshot(
    app: tauri::AppHandle,
    state: St<'_>,
    path: String,
    current_password: Option<String>,
) -> Result<(), CmdError> {
    // Same rule as an encrypted-backup restore, for the same reason. Rolling
    // the local file back while Drive is attached does not roll the REMOTE
    // back: the engine still holds the checksum of what it last uploaded, so
    // it sees nothing to download, and the next edit pushes the older vault
    // over the newer remote wholesale. Anything a second device had synced in
    // between is gone.
    if crate::sync::status(&app).connected {
        return Err(CmdError::new(
            "sync_connected",
            "Disconnect Google Drive sync before restoring an earlier version.",
        ));
    }
    let authorization = crate::reauth::authorize(
        &app,
        "restore an earlier version of your vault",
        current_password,
    )
    .await?;
    if crate::sync::status(&app).connected {
        return Err(CmdError::new(
            "sync_connected",
            "Disconnect Google Drive sync before restoring an earlier version.",
        ));
    }
    let mut st = guard(state.inner())?;
    authorization.validate(&st)?;
    st.unlock_generation = st.unlock_generation.wrapping_add(1);
    #[cfg(target_os = "macos")]
    crate::protected_unlock::clear(&st.store)?;
    st.store.restore_snapshot(std::path::Path::new(&path))?;
    // Reload from disk; `from_bytes` yields a LOCKED vault by design.
    st.vault = st.store.load().ok();
    st.unlock_generation = st.unlock_generation.wrapping_add(1);
    st.clipboard.clear_on_lock();
    // The snapshot predates whatever the keychain device key now wraps, so a
    // Touch ID unlock against it can only fail. Left in place it fails on
    // EVERY launch: the header has no device slot, so the staleness check that
    // would normally self-heal never fires. Drop the key with the vault.
    {
        let AppState { store, vault, .. } = &mut *st;
        if let Some(vault) = vault.as_mut() {
            let _ = store.disable_quick_unlock(vault);
        }
    }
    st.touch();
    drop(st);
    #[cfg(target_os = "macos")]
    let _ = vault_sharedkey::clear();
    let _ = app.emit("vault-locked", "restored");
    Ok(())
}

/// Copy the encrypted vault to `path` as an off-device backup.
///
/// The file is the same ciphertext the app stores, so it is useless without the
/// master password: no biometric gate is needed and nothing is decrypted here.
/// It can be verified and restored with [`restore_vault_backup`].
#[tauri::command]
pub fn export_vault_backup(state: St<'_>, path: String) -> Result<u64, CmdError> {
    let st = guard(state.inner())?;
    if !st.store.exists() {
        return Err(CmdError::new("no_vault", "There is no vault file yet."));
    }
    Ok(st.store.export_backup(std::path::Path::new(&path))?)
}

const MAX_BACKUP_BYTES: u64 = 256 * 1024 * 1024;

fn load_backup_candidate(
    path: &std::path::Path,
    master_password: String,
) -> Result<Vault, CmdError> {
    let metadata = std::fs::metadata(path)
        .map_err(|_| CmdError::new("backup_read", "Could not read that backup file."))?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_BACKUP_BYTES {
        return Err(CmdError::new(
            "invalid_backup",
            "That file is not a supported Arca backup.",
        ));
    }
    let bytes = std::fs::read(path)
        .map_err(|_| CmdError::new("backup_read", "Could not read that backup file."))?;
    let mut candidate = Vault::from_bytes(&bytes)?;
    let master_password = zeroize::Zeroizing::new(master_password);
    candidate.unlock(&master_password)?;
    // A device-wrapped key belongs to the machine that wrote the backup. Do
    // not import a stale biometric binding that can never succeed here.
    candidate.disable_device_unlock()?;
    Ok(candidate)
}

/// Replace the live vault with a verified encrypted backup.
///
/// The candidate is parsed and fully decrypted before the current file is
/// touched. `VaultStore::save` snapshots the current vault and atomically
/// writes the replacement, making the restore itself recoverable. Drive sync
/// must be disconnected first: silently attaching a different restored vault
/// to an existing remote identity would create an ambiguous, unsafe merge.
#[tauri::command]
pub async fn restore_vault_backup(
    app: tauri::AppHandle,
    state: St<'_>,
    path: String,
    master_password: String,
    current_password: Option<String>,
) -> Result<(), CmdError> {
    let authorization =
        crate::reauth::authorize(&app, "replace your vault with a backup", current_password)
            .await?;
    if crate::sync::status(&app).connected {
        return Err(CmdError::new(
            "sync_connected",
            "Disconnect Google Drive sync before restoring a backup.",
        ));
    }
    let mut candidate = tauri::async_runtime::spawn_blocking(move || {
        load_backup_candidate(std::path::Path::new(&path), master_password)
    })
    .await
    .map_err(|_| CmdError::new("internal", "Backup verification failed."))??;

    // The password check is intentionally off-thread and may take a while.
    // Re-check after it to close the window where sync could have been
    // connected while Argon2 was running.
    if crate::sync::status(&app).connected {
        return Err(CmdError::new(
            "sync_connected",
            "Disconnect Google Drive sync before restoring a backup.",
        ));
    }

    // Do not keep the replacement unlocked alongside UI state that belonged to
    // the old vault. The lock event clears details, searches and browser mirrors;
    // the user then explicitly unlocks the restored generation. Lock before
    // touching disk so a rare reseal failure leaves the current vault intact.
    candidate.lock()?;
    let mut st = guard(state.inner())?;
    authorization.validate(&st)?;
    st.unlock_generation = st.unlock_generation.wrapping_add(1);
    st.clipboard.clear_on_lock();
    #[cfg(target_os = "macos")]
    crate::protected_unlock::clear(&st.store)?;
    st.store.save(&candidate)?;
    st.vault = Some(candidate);
    // `load_backup_candidate` cleared the restored HEADER's device slot, but
    // the keychain still holds this machine's old device key. That combination
    // reports quick-unlock as available while it can never succeed, so every
    // launch opened a Touch ID prompt and answered it with "Incorrect password,
    // or the vault data is corrupt". Delete the key to match the header.
    {
        let AppState { store, vault, .. } = &mut *st;
        if let Some(vault) = vault.as_mut() {
            let _ = store.disable_quick_unlock(vault);
        }
    }
    st.touch();
    drop(st);

    #[cfg(target_os = "macos")]
    let _ = vault_sharedkey::clear();
    publish_identities(&app);
    let _ = app.emit("vault-locked", "backup-restored");
    Ok(())
}

/// Merge duplicate logins (same site + username). Losers go to the Trash;
/// returns how many were merged away.
#[tauri::command]
pub fn merge_duplicates(state: St<'_>) -> Result<usize, CmdError> {
    let mut st = write_guard(state.inner())?;
    let merged = {
        let vault = st.vault.as_mut().ok_or_else(CmdError::no_vault)?;
        vault.merge_duplicate_logins(crate::state::now_millis())?
    };
    if merged > 0 {
        persist(&mut st)?;
    }
    st.touch();
    Ok(merged)
}

// ---- Google Drive sync ----------------------------------------------------

/// Interactive Google sign-in (opens the browser; blocks until the redirect).
/// Runs the flow on a thread via async so the UI stays responsive.
#[tauri::command]
pub async fn sync_connect(app: tauri::AppHandle) -> Result<String, CmdError> {
    tauri::async_runtime::spawn_blocking(move || {
        crate::sync::connect(&app).map_err(|m| CmdError::new("sync_connect", &m))
    })
    .await
    .map_err(|_| CmdError::new("internal", "sign-in task failed"))?
}

#[tauri::command]
pub fn sync_disconnect(app: tauri::AppHandle) {
    crate::sync::disconnect(&app);
}

#[tauri::command]
pub fn sync_status(app: tauri::AppHandle) -> crate::sync::SyncStatusDto {
    crate::sync::status(&app)
}

/// One manual sync cycle; returns true if remote changes were merged in.
#[tauri::command]
pub async fn sync_now(app: tauri::AppHandle) -> Result<bool, CmdError> {
    tauri::async_runtime::spawn_blocking(move || {
        crate::sync::sync_now(&app).map_err(|m| CmdError::new("sync_failed", &m))
    })
    .await
    .map_err(|_| CmdError::new("internal", "sync task failed"))?
}

/// First-run restore: adopt the vault already in the signed-in Google account
/// as this device's vault, unlocked. The answer to "do you already have a
/// vault?" — creating a fresh one here would mint a new vault key and every
/// later sync would refuse the real vault as foreign. Requires a completed
/// `sync_connect` and no local vault file.
#[tauri::command]
pub async fn sync_bootstrap(
    app: tauri::AppHandle,
    master_password: String,
) -> Result<(), CmdError> {
    let bootstrapped = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        crate::sync::bootstrap(&bootstrapped, &master_password)
            .map_err(|m| CmdError::new("sync_bootstrap", &m))
    })
    .await
    .map_err(|_| CmdError::new("internal", "restore task failed"))??;
    // Same follow-through as a password unlock: the vault is open now.
    publish_identities(&app);
    kick_sync(&app);
    Ok(())
}

/// Re-key the vault under a new master password. Requires an unlocked vault and
/// a fresh biometric re-auth (Touch ID / Windows Hello; no-op where absent) so a
/// walk-up attacker at an unlocked machine can't silently rotate the password
/// and lock the owner out. Quick-unlock stays valid: the device-wrapped copy of
/// the vault key is untouched by rotation.
#[tauri::command]
pub async fn change_master_password(
    app: tauri::AppHandle,
    state: St<'_>,
    new_password: String,
    current_password: Option<String>,
) -> Result<(), CmdError> {
    if new_password.chars().count() < 8 {
        return Err(CmdError::new(
            "weak_password",
            "Use at least 8 characters for the master password.",
        ));
    }
    // Re-auth BEFORE taking the state lock (the prompt blocks on the user).
    let authorization =
        crate::reauth::authorize(&app, "change your master password", current_password).await?;

    let mut st = write_guard(state.inner())?;
    authorization.validate(&st)?;
    {
        let vault = st.vault.as_mut().ok_or_else(CmdError::no_vault)?;
        vault.change_master_password(&new_password)?;
    }
    persist(&mut st)?;
    st.touch();
    Ok(())
}

#[tauri::command]
pub fn disable_quick_unlock(state: St<'_>) -> Result<(), CmdError> {
    let mut st = write_guard(state.inner())?;
    if !st.vault()?.is_unlocked() {
        return Err(CmdError::new("locked", "Unlock the vault first."));
    }
    st.unlock_generation = st.unlock_generation.wrapping_add(1);
    #[cfg(target_os = "macos")]
    crate::protected_unlock::clear(&st.store)?;
    {
        let AppState { store, vault, .. } = &mut *st;
        let vault = vault.as_mut().ok_or_else(CmdError::no_vault)?;
        store.disable_quick_unlock(vault)?;
    }
    // Turning quick unlock off must also take away the extension's copy.
    // Leaving it behind would let AutoFill go on opening the vault with a key
    // the user just revoked.
    #[cfg(target_os = "macos")]
    let _ = vault_sharedkey::clear();
    persist(&mut st)?;
    st.touch();
    Ok(())
}

/// Lock on the user's own command (the sidebar button).
///
/// Emits `vault-locked` exactly like the tray item and the automatic locks. It
/// used to stay silent, so the UI never ran its clearing pass: decrypted items,
/// the open detail and the security report stayed in webview state, and the
/// lock screen — seeing no automatic lock — immediately opened a Touch ID sheet
/// asking to unlock the vault the user had just deliberately locked.
#[tauri::command]
pub fn lock(app: tauri::AppHandle, state: St<'_>) -> Result<(), CmdError> {
    let mut st = guard(state.inner())?;
    st.lock()?;
    drop(st);
    let _ = app.emit("vault-locked", "user");
    Ok(())
}

/// Reset the idle timer; the frontend calls this on GENUINE user interaction.
///
/// Note what does not call it: `list_items`, `security_report` and `get_item`.
/// Those run on a timer and on every `sync-merged` event, so a phone quietly
/// editing entries kept pushing the desktop's idle deadline out and the vault
/// never locked — in exactly the situation idle-lock exists for, the user being
/// somewhere else. Reads the app performs by itself are not evidence of a human
/// at the keyboard; revealing, copying, searching and editing still are.
#[tauri::command]
pub fn touch(state: St<'_>) -> Result<(), CmdError> {
    guard(state.inner())?.touch();
    Ok(())
}

// ---- item commands --------------------------------------------------------

#[tauri::command]
pub fn list_items(state: St<'_>, include_deleted: bool) -> Result<Vec<ItemSummaryDto>, CmdError> {
    do_list_items(state.inner(), include_deleted)
}

fn do_list_items(
    state: &Mutex<AppState>,
    include_deleted: bool,
) -> Result<Vec<ItemSummaryDto>, CmdError> {
    let st = guard(state)?;
    let summaries = st.vault()?.list_items(include_deleted)?;
    Ok(summaries
        .into_iter()
        .map(|s| ItemSummaryDto {
            is_sync_conflict: s.is_sync_conflict,
            conflict_of: s.conflict_of.map(|id| id.to_string()),
            id: s.id.to_string(),
            kind: kind_str(s.kind).to_string(),
            letter: first_letter(&s.title),
            host: crate::bridge::host_of(&s.url),
            folder: s.folder,
            title: s.title,
            subtitle: s.subtitle,
            has_totp: s.has_totp,
            is_deleted: s.is_deleted,
            modified_at: s.modified_at,
        })
        .collect())
}

#[tauri::command]
pub fn search_items(
    state: St<'_>,
    query: String,
    include_deleted: bool,
) -> Result<Vec<String>, CmdError> {
    do_search_items(state.inner(), &query, include_deleted)
}

fn do_search_items(
    state: &Mutex<AppState>,
    query: &str,
    include_deleted: bool,
) -> Result<Vec<String>, CmdError> {
    let query = query.trim().to_lowercase();
    let mut st = guard(state)?;
    st.touch();
    let vault = st.vault()?;
    let summaries = vault.list_items(include_deleted)?;
    if query.is_empty() {
        return Ok(summaries
            .into_iter()
            .map(|item| item.id.to_string())
            .collect());
    }
    let mut ids = Vec::new();
    for summary in summaries {
        let item = vault.get_item(summary.id)?;
        if item_matches_query(&item.data, &query) {
            ids.push(summary.id.to_string());
        }
    }
    Ok(ids)
}

#[tauri::command]
pub fn get_item(state: St<'_>, id: String) -> Result<ItemDetailDto, CmdError> {
    do_get_item(state.inner(), &id)
}

fn do_get_item(state: &Mutex<AppState>, id: &str) -> Result<ItemDetailDto, CmdError> {
    let st = guard(state)?;
    let item = st.vault()?.get_item(parse_id(id)?)?;
    let (title, username, url, notes, has_password, has_totp, password_strength) = match &item.data
    {
        VaultItem::Login {
            title,
            username,
            url,
            notes,
            password,
            totp_secret,
        } => (
            title.clone(),
            username.clone(),
            url.clone(),
            notes.clone(),
            !password.is_empty(),
            totp_secret
                .as_deref()
                .map(|s| !s.is_empty())
                .unwrap_or(false),
            if password.is_empty() {
                None
            } else {
                Some(strength_str(estimate_strength(password)).to_string())
            },
        ),
        VaultItem::Wifi {
            title,
            password,
            notes,
            ..
        } => (
            title.clone(),
            String::new(),
            String::new(),
            notes.clone(),
            !password.is_empty(),
            false,
            if password.is_empty() {
                None
            } else {
                Some(strength_str(estimate_strength(password)).to_string())
            },
        ),
        // Secure note: the body rides in `notes` (shown directly in the detail
        // pane, like a login's notes; the vault is unlocked to view it).
        VaultItem::SecureNote { title, body } => (
            title.clone(),
            String::new(),
            String::new(),
            body.clone(),
            false,
            false,
            None,
        ),
        // A bookmark's URL is the whole point of it, so it must not fall into
        // the stub arm below and arrive with nothing but a title.
        VaultItem::Bookmark {
            title, url, notes, ..
        } => (
            title.clone(),
            String::new(),
            url.clone(),
            notes.clone(),
            false,
            false,
            None,
        ),
        // Stub kinds expose only their title for now.
        other => (
            other.title().to_string(),
            String::new(),
            String::new(),
            String::new(),
            false,
            false,
            None,
        ),
    };
    // Wi-Fi-only metadata (empty/false for every other kind).
    let (ssid, security, hidden) = match &item.data {
        VaultItem::Wifi {
            ssid,
            security,
            hidden,
            ..
        } => (ssid.clone(), security.clone(), *hidden),
        _ => (String::new(), String::new(), false),
    };
    let folder = match &item.data {
        VaultItem::Bookmark { folder, .. } => folder.clone(),
        _ => String::new(),
    };
    Ok(ItemDetailDto {
        id: item.id.to_string(),
        kind: kind_str(item.data.kind()).to_string(),
        title,
        username,
        url,
        notes,
        has_password,
        has_totp,
        password_strength,
        is_deleted: item.is_deleted(),
        created_at: item.created_at,
        modified_at: item.modified_at,
        ssid,
        security,
        hidden,
        folder,
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BreachHit {
    pub id: String,
    /// How many times the password appears in known breaches.
    pub count: u64,
}

/// Outcome of a breach check.
///
/// `unchecked` matters: a login whose range request failed is NOT known to be
/// clean, and reporting only `hits` would turn a network problem into a false
/// all-clear on a security feature.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BreachReport {
    pub hits: Vec<BreachHit>,
    /// Logins actually compared against the breach corpus.
    pub checked: usize,
    /// Logins skipped because their range could not be fetched.
    pub unchecked: usize,
}

/// Check every login password against HaveIBeenPwned using k-anonymity: only the
/// 5-char SHA-1 prefix leaves the device, never the password or its full hash.
/// The password plaintext is touched only briefly under the state lock (to hash
/// it); the network calls run afterward with just the hashes.
#[tauri::command]
pub async fn check_breaches(
    app: tauri::AppHandle,
    state: St<'_>,
) -> Result<BreachReport, CmdError> {
    // (id, prefix, suffix) for every login, computed under the lock.
    let entries: Vec<(String, String, String)> = {
        let st = guard(state.inner())?;
        let vault = st.vault.as_ref().ok_or_else(CmdError::no_vault)?;
        if !vault.is_unlocked() {
            return Err(CmdError::new("locked", "Unlock the vault first."));
        }
        let mut out = Vec::new();
        if let Ok(summaries) = vault.list_items(false) {
            for s in summaries {
                if let Ok(item) = vault.get_item(s.id) {
                    if let VaultItem::Login { password, .. } = &item.data {
                        if !password.is_empty() {
                            let (p, suf) = vault_core::breach::prefix_suffix(password);
                            out.push((item.id.to_string(), p, suf));
                        }
                    }
                }
            }
        }
        out
    };
    if entries.is_empty() {
        return Ok(BreachReport {
            hits: Vec::new(),
            checked: 0,
            unchecked: 0,
        });
    }

    tauri::async_runtime::spawn_blocking(move || {
        use std::collections::{HashMap, HashSet};
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, Mutex};

        // Fetch each DISTINCT prefix exactly once. Work used to be split by
        // login, with a per-worker cache, so a vault with reused passwords (or
        // simply two logins whose hashes share a prefix) fetched the same range
        // several times: ~640 requests for ~640 logins, minutes of waiting. Only
        // the prefix set actually costs network time; matching suffixes is local.
        let prefixes: Vec<String> = entries
            .iter()
            .map(|(_, p, _)| p.clone())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        let total = prefixes.len();

        // Each response is padded to a uniform ~80 KB, so latency dominates and
        // concurrency is what helps. The range API is a cached, public endpoint
        // designed for exactly this.
        const WORKERS: usize = 16;

        let prefixes = Arc::new(prefixes);
        let ranges: Arc<Mutex<HashMap<String, String>>> = Arc::default();
        let next = Arc::new(AtomicUsize::new(0));
        let done = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::new();
        for _ in 0..WORKERS.min(total.max(1)) {
            let (prefixes, ranges, next, done) = (
                Arc::clone(&prefixes),
                Arc::clone(&ranges),
                Arc::clone(&next),
                Arc::clone(&done),
            );
            let app = app.clone();
            handles.push(std::thread::spawn(move || {
                let Ok(client) = reqwest::blocking::Client::builder()
                    .timeout(std::time::Duration::from_secs(20))
                    .build()
                else {
                    return;
                };
                // Pull from a shared cursor rather than a fixed slice, so one
                // slow response cannot leave other workers idle.
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(prefix) = prefixes.get(i) else { break };
                    // One retry: the endpoint is rate-limited and throughput
                    // measured wildly variable, so a single failure is usually
                    // transient — and an unfetched prefix means those logins go
                    // UNCHECKED, which must never be reported as "no breaches".
                    let mut body = None;
                    for attempt in 0..2 {
                        if attempt > 0 {
                            std::thread::sleep(std::time::Duration::from_millis(750));
                        }
                        // `Add-Padding` makes every response a uniform size, so
                        // an on-path observer cannot infer the prefix from it.
                        body = client
                            .get(format!("https://api.pwnedpasswords.com/range/{prefix}"))
                            .header("Add-Padding", "true")
                            .send()
                            .and_then(reqwest::blocking::Response::error_for_status)
                            .and_then(reqwest::blocking::Response::text)
                            .ok();
                        if body.is_some() {
                            break;
                        }
                    }
                    if let Some(body) = body {
                        if let Ok(mut map) = ranges.lock() {
                            map.insert(prefix.clone(), body);
                        }
                    }
                    let n = done.fetch_add(1, Ordering::Relaxed) + 1;
                    // Minutes of indeterminate spinner is not acceptable UI.
                    let _ = app.emit("breach-progress", (n, total));
                }
            }));
        }
        for h in handles {
            let _ = h.join();
        }

        let ranges = ranges
            .lock()
            .map_err(|_| CmdError::new("internal", "breach-check task failed"))?;
        let mut hits = Vec::new();
        // Logins whose range never arrived are UNCHECKED, not clean. Counting
        // them lets the UI say so instead of implying an all-clear.
        let mut unchecked = 0usize;
        for (id, prefix, suffix) in &entries {
            match ranges.get(prefix) {
                Some(body) => {
                    if let Some(count) = vault_core::breach::count_in_range(suffix, body) {
                        hits.push(BreachHit {
                            id: id.clone(),
                            count,
                        });
                    }
                }
                None => unchecked += 1,
            }
        }
        Ok(BreachReport {
            checked: entries.len() - unchecked,
            unchecked,
            hits,
        })
    })
    .await
    .map_err(|_| CmdError::new("internal", "breach-check task failed"))?
}

/// Password-health audit (weak/reused) over the active login items.
#[tauri::command]
pub fn security_report(state: St<'_>) -> Result<Vec<SecurityIssueDto>, CmdError> {
    do_security_report(state.inner())
}

fn do_security_report(state: &Mutex<AppState>) -> Result<Vec<SecurityIssueDto>, CmdError> {
    let st = guard(state)?;
    let report = st.vault()?.security_report()?;
    Ok(report
        .into_iter()
        .map(|r| SecurityIssueDto {
            id: r.id.to_string(),
            issues: r
                .issues
                .into_iter()
                .map(|i| issue_str(i).to_string())
                .collect(),
        })
        .collect())
}

/// Import logins from a CSV export at `path` (Chrome/Brave/Edge, Apple
/// Passwords, Firefox, or a generic header-mapped layout). The file is read in
/// Rust, so the exported plaintext passwords never pass through the webview.
#[tauri::command]
pub fn import_logins(state: St<'_>, path: String) -> Result<ImportSummary, CmdError> {
    do_import_logins(state.inner(), &path)
}

fn do_import_logins(state: &Mutex<AppState>, path: &str) -> Result<ImportSummary, CmdError> {
    let text = std::fs::read_to_string(path)
        .map_err(|_| CmdError::new("io", "Could not read the selected file."))?;
    let (parsed, skipped) = parse_logins_csv(&text);

    let mut st = write_guard(state)?;
    st.touch();
    let now = now_millis();

    // Index existing active logins by (normalized host, lowercased username) so
    // re-importing an export updates/skips instead of duplicating. Entries
    // without a URL are never merged (a bare username is too weak an identity).
    let mut by_key: std::collections::HashMap<(String, String), Uuid> = st
        .vault()?
        .list_items(false)?
        .into_iter()
        .filter(|s| !crate::bridge::host_of(&s.url).is_empty())
        .map(|s| {
            let key = (crate::bridge::host_of(&s.url), s.subtitle.to_lowercase());
            (key, s.id)
        })
        .collect();

    let mut imported = 0usize;
    let mut updated = 0usize;
    let mut duplicates = 0usize;
    for p in parsed {
        // A bad/unsupported TOTP value shouldn't drop the whole login: keep the
        // credentials and just omit the code.
        let totp_secret = normalize_totp_secret(if p.totp.is_empty() {
            None
        } else {
            Some(p.totp)
        })
        .unwrap_or(None);

        let host = crate::bridge::host_of(&p.url);
        let key = (host.clone(), p.username.to_lowercase());
        let existing = if host.is_empty() {
            None
        } else {
            by_key.get(&key).copied()
        };

        if let Some(id) = existing {
            let current = st.vault()?.get_item(id)?;
            let (cur_title, cur_username, cur_url, cur_password, cur_totp, cur_notes) =
                match &current.data {
                    VaultItem::Login {
                        title,
                        username,
                        url,
                        password,
                        totp_secret,
                        notes,
                    } => (
                        title.clone(),
                        username.clone(),
                        url.clone(),
                        password.clone(),
                        totp_secret.clone(),
                        notes.clone(),
                    ),
                    // The merge key comes from a Login summary, so a non-Login
                    // hit is impossible; treat it as "not found" defensively.
                    _ => {
                        let item = Item::new(
                            VaultItem::Login {
                                title: p.title,
                                username: p.username,
                                password: p.password,
                                url: p.url,
                                totp_secret,
                                notes: p.notes,
                            },
                            now,
                        );
                        st.vault_mut()?.upsert_item(item)?;
                        imported += 1;
                        continue;
                    }
                };

            // Merge, never destroy: an empty CSV column keeps the existing
            // value (so a username-only row can't wipe a stored password, and a
            // browser export without TOTP/notes doesn't erase them). Title/URL/
            // username are the user's to own — imports refresh secrets, they
            // don't overwrite labels the user may have customized.
            let new_password = if p.password.is_empty() {
                cur_password.clone()
            } else {
                p.password
            };
            let new_totp = totp_secret.or_else(|| cur_totp.clone());
            let new_notes = if p.notes.is_empty() {
                cur_notes.clone()
            } else {
                p.notes
            };

            let changed =
                new_password != cur_password || new_totp != cur_totp || new_notes != cur_notes;
            if !changed {
                duplicates += 1;
                continue;
            }

            let item = Item {
                id: current.id,
                created_at: current.created_at,
                modified_at: now,
                deleted_at: None,
                revision: current.revision,
                revision_ancestors: current.revision_ancestors.clone(),
                password_history: current.password_history.clone(),
                sync_conflict: current.sync_conflict.clone(),
                data: VaultItem::Login {
                    title: cur_title,
                    username: cur_username,
                    url: cur_url,
                    password: new_password,
                    totp_secret: new_totp,
                    notes: new_notes,
                },
            };
            st.vault_mut()?.upsert_item(item)?;
            updated += 1;
            continue;
        }

        let item = Item::new(
            VaultItem::Login {
                title: p.title,
                username: p.username,
                password: p.password,
                url: p.url,
                totp_secret,
                notes: p.notes,
            },
            now,
        );
        // Register the new item so a second row for the same site + username
        // within this file dedupes against it instead of importing twice.
        if !host.is_empty() {
            by_key.insert(key, item.id);
        }
        st.vault_mut()?.upsert_item(item)?;
        imported += 1;
    }
    if imported > 0 || updated > 0 {
        persist(&mut st)?;
    }
    Ok(ImportSummary {
        imported,
        updated,
        duplicates,
        skipped,
    })
}

/// Open the system password manager app (macOS "Passwords"), as a convenience
/// next to the Safari/Apple import instructions. No-op elsewhere.
#[tauri::command]
pub fn open_passwords_app() -> Result<(), CmdError> {
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .args(["-a", "Passwords"])
            .spawn()
            .map_err(|_| CmdError::new("io", "Could not open the Passwords app."))?;
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err(CmdError::new(
            "unsupported",
            "Opening the system password manager is only wired up on macOS.",
        ))
    }
}

/// Reveal a single secret field on demand (for display in the UI).
/// `field` is one of `"password"`, `"totp_secret"`, `"notes"`.
#[tauri::command]
pub fn reveal_field(state: St<'_>, id: String, field: String) -> Result<String, CmdError> {
    do_reveal_field(state.inner(), &id, &field)
}

fn do_reveal_field(state: &Mutex<AppState>, id: &str, field: &str) -> Result<String, CmdError> {
    let mut st = guard(state)?;
    st.touch();
    let item = st.vault()?.get_item(parse_id(id)?)?;
    secret_field(&item, field)
}

/// Copy a secret field to the clipboard via the owner thread (plaintext never
/// reaches the webview); auto-clears after the configured timeout.
#[tauri::command]
pub fn copy_field(state: St<'_>, id: String, field: String) -> Result<(), CmdError> {
    do_copy_field(state.inner(), &id, &field)
}

fn do_copy_field(state: &Mutex<AppState>, id: &str, field: &str) -> Result<(), CmdError> {
    let (clipboard, text, clear_secs) = {
        let mut st = guard(state)?;
        st.touch();
        let item = st.vault()?.get_item(parse_id(id)?)?;
        (
            st.clipboard.clone(),
            secret_field(&item, field)?,
            st.settings.clipboard_clear_secs,
        )
    }; // release the lock before handing off to the clipboard thread
    clipboard.copy(text, clear_secs);
    Ok(())
}

/// Copy arbitrary (non-secret, e.g. username) text to the clipboard, also with
/// auto-clear for consistency.
#[tauri::command]
pub fn copy_to_clipboard(state: St<'_>, text: String) -> Result<(), CmdError> {
    let (clipboard, clear_secs) = {
        let mut st = guard(state.inner())?;
        st.touch();
        (st.clipboard.clone(), st.settings.clipboard_clear_secs)
    };
    clipboard.copy(text, clear_secs);
    Ok(())
}

#[tauri::command]
pub fn upsert_item(state: St<'_>, input: LoginInput) -> Result<String, CmdError> {
    do_upsert_item(state.inner(), input)
}

pub(crate) fn do_upsert_item(
    state: &Mutex<AppState>,
    input: LoginInput,
) -> Result<String, CmdError> {
    let mut st = write_guard(state)?;
    st.touch();
    let now = now_millis();
    let data = VaultItem::Login {
        title: input.title,
        username: input.username,
        password: input.password,
        url: input.url,
        totp_secret: normalize_totp_secret(input.totp_secret)?,
        notes: input.notes,
    };

    let id = match input.id {
        Some(id_str) => {
            let uuid = parse_id(&id_str)?;
            // Preserve the original creation time on edit.
            let mut existing = st.vault()?.get_item(uuid)?;
            require_kind(&existing, ItemKind::Login)?;
            existing.data = data;
            existing.modified_at = now;
            st.vault_mut()?.upsert_item(existing)?;
            uuid
        }
        None => {
            let item = Item::new(data, now);
            let new_id = item.id;
            st.vault_mut()?.upsert_item(item)?;
            new_id
        }
    };
    persist(&mut st)?;
    Ok(id.to_string())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WifiInput {
    pub id: Option<String>,
    pub title: String,
    pub ssid: String,
    pub password: String,
    /// "WPA" | "WEP" | "nopass".
    pub security: String,
    pub hidden: bool,
    pub notes: String,
}

/// Create or update a Wi-Fi network item.
#[tauri::command]
pub fn upsert_wifi(state: St<'_>, input: WifiInput) -> Result<String, CmdError> {
    let mut st = write_guard(state.inner())?;
    st.touch();
    let now = now_millis();
    // Title defaults to the SSID when left blank.
    let title = if input.title.trim().is_empty() {
        input.ssid.clone()
    } else {
        input.title
    };
    let data = VaultItem::Wifi {
        title,
        ssid: input.ssid,
        password: input.password,
        security: input.security,
        hidden: input.hidden,
        notes: input.notes,
    };
    let id = match input.id {
        Some(id_str) => {
            let uuid = parse_id(&id_str)?;
            let mut existing = st.vault()?.get_item(uuid)?;
            require_kind(&existing, ItemKind::Wifi)?;
            existing.data = data;
            existing.modified_at = now;
            st.vault_mut()?.upsert_item(existing)?;
            uuid
        }
        None => {
            let item = Item::new(data, now);
            let new_id = item.id;
            st.vault_mut()?.upsert_item(item)?;
            new_id
        }
    };
    persist(&mut st)?;
    Ok(id.to_string())
}

/// Render a "join this network" QR code (SVG) for a Wi-Fi item. The passphrase
/// is encoded into the QR here in Rust, so the plaintext never crosses to the
/// webview as readable text — only the SVG image does.
#[tauri::command]
pub fn wifi_qr(state: St<'_>, id: String) -> Result<String, CmdError> {
    let st = guard(state.inner())?;
    let item = st.vault()?.get_item(parse_id(&id)?)?;
    let VaultItem::Wifi {
        ssid,
        password,
        security,
        hidden,
        ..
    } = &item.data
    else {
        return Err(CmdError::new(
            "not_wifi",
            "This item is not a Wi-Fi network.",
        ));
    };
    let payload = vault_core::wifi_qr_payload(ssid, password, security, *hidden);
    let code = qrcode::QrCode::new(payload.as_bytes())
        .map_err(|_| CmdError::new("qr_failed", "Could not build the QR code."))?;
    let svg = code
        .render::<qrcode::render::svg::Color>()
        .min_dimensions(200, 200)
        .quiet_zone(true)
        .dark_color(qrcode::render::svg::Color("#111111"))
        .light_color(qrcode::render::svg::Color("#ffffff"))
        .build();
    Ok(svg)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecureNoteInput {
    pub id: Option<String>,
    pub title: String,
    pub body: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BookmarkInput {
    pub id: Option<String>,
    pub title: String,
    pub url: String,
    pub folder: String,
    pub notes: String,
}

/// Create or update a bookmark. Only web URLs are accepted: launching a
/// bookmarklet or local file from a password manager's privileged surface is
/// both surprising and unnecessarily dangerous.
#[tauri::command]
pub fn upsert_bookmark(state: St<'_>, input: BookmarkInput) -> Result<String, CmdError> {
    do_upsert_bookmark(state.inner(), input)
}

fn do_upsert_bookmark(state: &Mutex<AppState>, input: BookmarkInput) -> Result<String, CmdError> {
    let raw_url = input.url.trim();
    let candidate = if raw_url.contains("://") {
        raw_url.to_string()
    } else {
        format!("https://{raw_url}")
    };
    let parsed = url::Url::parse(&candidate)
        .map_err(|_| CmdError::new("invalid_url", "Enter a valid web address."))?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return Err(CmdError::new(
            "invalid_url",
            "Bookmarks must use an http or https address.",
        ));
    }
    let title = if input.title.trim().is_empty() {
        parsed.host_str().unwrap_or("Bookmark").to_string()
    } else {
        input.title.trim().to_string()
    };
    let data = VaultItem::Bookmark {
        title,
        url: parsed.to_string(),
        folder: normalize_bookmark_folder(&input.folder),
        notes: input.notes,
    };

    let mut st = write_guard(state)?;
    st.touch();
    let now = now_millis();
    let id = match input.id {
        Some(id) => {
            let id = parse_id(&id)?;
            let mut existing = st.vault()?.get_item(id)?;
            require_kind(&existing, ItemKind::Bookmark)?;
            existing.data = data;
            existing.modified_at = now;
            st.vault_mut()?.upsert_item(existing)?;
            id
        }
        None => {
            let item = Item::new(data, now);
            let id = item.id;
            st.vault_mut()?.upsert_item(item)?;
            id
        }
    };
    persist(&mut st)?;
    Ok(id.to_string())
}

/// Move several bookmarks in one validated save. All ids are checked before
/// the first mutation, so a stale selection cannot partially move a batch or
/// accidentally reinterpret a non-bookmark item.
#[tauri::command]
pub fn move_bookmarks(state: St<'_>, ids: Vec<String>, folder: String) -> Result<usize, CmdError> {
    do_move_bookmarks(state.inner(), ids, &folder)
}

fn do_move_bookmarks(
    state: &Mutex<AppState>,
    ids: Vec<String>,
    folder: &str,
) -> Result<usize, CmdError> {
    let mut seen = std::collections::HashSet::new();
    let ids = ids
        .iter()
        .map(|id| parse_id(id))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|id| seen.insert(*id))
        .collect::<Vec<_>>();
    if ids.is_empty() {
        return Ok(0);
    }

    let mut st = write_guard(state)?;
    st.touch();
    let mut items = Vec::with_capacity(ids.len());
    for id in ids {
        let item = st.vault()?.get_item(id)?;
        require_kind(&item, ItemKind::Bookmark)?;
        if item.is_deleted() {
            return Err(CmdError::new(
                "deleted_item",
                "Restore deleted bookmarks before moving them.",
            ));
        }
        items.push(item);
    }

    let folder = normalize_bookmark_folder(folder);
    let now = now_millis();
    let mut changed = 0;
    for mut item in items {
        let VaultItem::Bookmark {
            folder: current, ..
        } = &mut item.data
        else {
            unreachable!("validated above")
        };
        if *current == folder {
            continue;
        }
        *current = folder.clone();
        item.modified_at = now;
        st.vault_mut()?.upsert_item(item)?;
        changed += 1;
    }
    if changed > 0 {
        persist(&mut st)?;
    }
    Ok(changed)
}

/// Create or update a secure note (title + free-form encrypted body).
#[tauri::command]
pub fn upsert_secure_note(state: St<'_>, input: SecureNoteInput) -> Result<String, CmdError> {
    let mut st = write_guard(state.inner())?;
    st.touch();
    let now = now_millis();
    let title = if input.title.trim().is_empty() {
        "Untitled note".to_string()
    } else {
        input.title
    };
    let data = VaultItem::SecureNote {
        title,
        body: input.body,
    };
    let id = match input.id {
        Some(id_str) => {
            let uuid = parse_id(&id_str)?;
            let mut existing = st.vault()?.get_item(uuid)?;
            require_kind(&existing, ItemKind::SecureNote)?;
            existing.data = data;
            existing.modified_at = now;
            st.vault_mut()?.upsert_item(existing)?;
            uuid
        }
        None => {
            let item = Item::new(data, now);
            let new_id = item.id;
            st.vault_mut()?.upsert_item(item)?;
            new_id
        }
    };
    persist(&mut st)?;
    Ok(id.to_string())
}

/// Generate a fresh Ed25519 SSH key inside the vault. The private seed never
/// leaves; only the public identity is derived for display / authorized_keys.
#[tauri::command]
pub fn generate_ssh_key(state: St<'_>, comment: String) -> Result<String, CmdError> {
    let new_key =
        vault_core::ssh::generate(&comment).map_err(|_| CmdError::new("ssh", "Bad comment."))?;
    let mut st = write_guard(state.inner())?;
    st.touch();
    let title = if comment.trim().is_empty() {
        "SSH key".to_string()
    } else {
        comment.trim().to_string()
    };
    let data = VaultItem::SshKey {
        title,
        comment: comment.trim().to_string(),
        key_type: vault_core::ssh::ALGORITHM.to_string(),
        public_key: new_key.public_blob,
        private_key: new_key.private_key.to_vec(),
        fingerprint: new_key.fingerprint,
    };
    let item = Item::new(data, now_millis());
    let id = item.id;
    st.vault_mut()?.upsert_item(item)?;
    persist(&mut st)?;
    Ok(id.to_string())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SshPublicKey {
    /// Ready-to-paste `authorized_keys` line.
    pub authorized_key: String,
    /// OpenSSH SHA-256 fingerprint.
    pub fingerprint: String,
    pub comment: String,
}

/// The non-secret public material of an SSH key (for display / copy).
#[tauri::command]
pub fn ssh_public_key(state: St<'_>, id: String) -> Result<SshPublicKey, CmdError> {
    let st = guard(state.inner())?;
    let item = st.vault()?.get_item(parse_id(&id)?)?;
    let VaultItem::SshKey {
        public_key,
        comment,
        fingerprint,
        ..
    } = &item.data
    else {
        return Err(CmdError::new("not_ssh", "This item is not an SSH key."));
    };
    let authorized_key = vault_core::ssh::authorized_key_from_blob(public_key, comment)
        .map_err(|_| CmdError::new("ssh", "Could not render the public key."))?;
    Ok(SshPublicKey {
        authorized_key,
        fingerprint: fingerprint.clone(),
        comment: comment.clone(),
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SshAgentInfo {
    /// The agent's Unix-socket path (empty on platforms without it yet).
    pub socket: String,
    /// True where the ssh-agent transport is implemented (Unix today).
    pub available: bool,
}

/// Where the ssh-agent listens, for the "export SSH_AUTH_SOCK=..." hint.
#[tauri::command]
pub fn ssh_agent_info(app: tauri::AppHandle) -> SshAgentInfo {
    let path = crate::agent::socket_path(&app);
    let socket = path.to_string_lossy().to_string();
    SshAgentInfo {
        available: cfg!(any(unix, windows)) && !socket.is_empty(),
        socket,
    }
}

#[tauri::command]
pub fn delete_item(state: St<'_>, id: String) -> Result<(), CmdError> {
    do_delete_item(state.inner(), &id)
}

fn do_delete_item(state: &Mutex<AppState>, id: &str) -> Result<(), CmdError> {
    let mut st = write_guard(state)?;
    st.touch();
    let uuid = parse_id(id)?;
    st.vault_mut()?.delete_item(uuid, now_millis())?;
    persist(&mut st)?;
    Ok(())
}

#[tauri::command]
pub fn restore_item(state: St<'_>, id: String) -> Result<(), CmdError> {
    do_restore_item(state.inner(), &id)
}

fn do_restore_item(state: &Mutex<AppState>, id: &str) -> Result<(), CmdError> {
    let mut st = write_guard(state)?;
    st.touch();
    let uuid = parse_id(id)?;
    st.vault_mut()?.restore_item(uuid, now_millis())?;
    persist(&mut st)?;
    Ok(())
}

#[tauri::command]
pub fn purge_item(state: St<'_>, id: String) -> Result<(), CmdError> {
    do_purge_item(state.inner(), &id)
}

fn do_purge_item(state: &Mutex<AppState>, id: &str) -> Result<(), CmdError> {
    let mut st = write_guard(state)?;
    st.touch();
    let uuid = parse_id(id)?;
    st.vault_mut()?.purge_item(uuid, now_millis())?;
    persist(&mut st)?;
    Ok(())
}

#[tauri::command]
pub fn current_totp(state: St<'_>, id: String) -> Result<TotpDto, CmdError> {
    // Intentionally does NOT touch() — the UI polls this on a timer.
    let st = guard(state.inner())?;
    let item = st.vault()?.get_item(parse_id(&id)?)?;
    let secret = match &item.data {
        VaultItem::Login {
            totp_secret: Some(s),
            ..
        } if !s.is_empty() => s.clone(),
        _ => return Err(CmdError::new("no_totp", "This item has no TOTP secret.")),
    };
    let code = vault_core::current_totp(&secret, now_secs())?;
    Ok(TotpDto {
        code: code.code,
        period: code.period,
        remaining: code.remaining,
    })
}

// ---- utilities ------------------------------------------------------------

#[tauri::command]
pub fn generate(state: St<'_>, options: PasswordOptionsDto) -> Result<String, CmdError> {
    guard(state.inner())?.touch();
    let opts = PasswordOptions {
        length: options.length,
        lowercase: options.lowercase,
        uppercase: options.uppercase,
        digits: options.digits,
        symbols: options.symbols,
    };
    let pw = generate_password(&opts)?;
    Ok(pw.to_string())
}

#[tauri::command]
pub fn get_settings(state: St<'_>) -> Result<Settings, CmdError> {
    Ok(guard(state.inner())?.settings)
}

#[tauri::command]
pub fn set_settings(state: St<'_>, settings: Settings) -> Result<(), CmdError> {
    let mut st = guard(state.inner())?;
    crate::state::save_settings(st.store.path(), &settings)
        .map_err(|_| CmdError::new("io", "Could not save settings."))?;
    st.settings = settings;
    st.touch();
    Ok(())
}

/// Temporarily suppress blur-based auto-lock. The frontend sets this around its
/// own native dialogs (e.g. the import file picker), which blur the main window
/// without the user actually leaving the app.
#[tauri::command]
pub fn set_blur_lock_suppressed(state: St<'_>, suppressed: bool) -> Result<(), CmdError> {
    guard(state.inner())?.suppress_blur_lock = suppressed;
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppInfo {
    version: &'static str,
    build: &'static str,
    platform: &'static str,
    vault_format: u8,
}

#[tauri::command]
pub fn app_info() -> AppInfo {
    AppInfo {
        version: env!("CARGO_PKG_VERSION"),
        build: env!("ARCA_BUILD"),
        platform: std::env::consts::OS,
        vault_format: 5,
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordHistoryDto {
    id: String,
    replaced_at: i64,
}

#[tauri::command]
pub fn password_history(state: St<'_>, id: String) -> Result<Vec<PasswordHistoryDto>, CmdError> {
    let mut st = guard(state.inner())?;
    st.touch();
    Ok(st
        .vault()?
        .get_item(parse_id(&id)?)?
        .password_history
        .iter()
        .map(|entry| PasswordHistoryDto {
            id: entry.id.to_string(),
            replaced_at: entry.replaced_at,
        })
        .collect())
}

#[tauri::command]
pub fn copy_password_history(state: St<'_>, id: String, revision: String) -> Result<(), CmdError> {
    let (clipboard, text, seconds) = {
        let mut st = guard(state.inner())?;
        st.touch();
        let item = st.vault()?.get_item(parse_id(&id)?)?;
        let revision = parse_id(&revision)?;
        let text = item
            .password_history
            .iter()
            .find(|h| h.id == revision)
            .ok_or_else(|| CmdError::new("not_found", "Password history entry not found."))?
            .password
            .clone();
        (st.clipboard.clone(), text, st.settings.clipboard_clear_secs)
    };
    clipboard.copy(text, seconds);
    Ok(())
}

#[tauri::command]
pub fn restore_password_history(
    state: St<'_>,
    id: String,
    revision: String,
) -> Result<(), CmdError> {
    do_restore_password_history(state.inner(), &id, &revision)
}

fn do_restore_password_history(
    state: &Mutex<AppState>,
    id: &str,
    revision: &str,
) -> Result<(), CmdError> {
    let mut st = write_guard(state)?;
    st.touch();
    st.vault_mut()?
        .restore_password(parse_id(id)?, parse_id(revision)?, now_millis())?;
    persist(&mut st)
}

#[tauri::command]
pub async fn verify_vault_backup(path: String, master_password: String) -> Result<(), CmdError> {
    tauri::async_runtime::spawn_blocking(move || {
        load_backup_candidate(std::path::Path::new(&path), master_password).map(|_| ())
    })
    .await
    .map_err(|_| CmdError::new("backup", "Backup verification stopped."))?
}

/// A browser profile Arca can read bookmarks from.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BookmarkSourceDto {
    pub label: String,
    pub path: String,
    /// How many bookmarks this profile holds right now.
    pub count: usize,
}

/// Browser profiles on this machine whose bookmarks Arca can read.
#[tauri::command]
pub fn list_bookmark_sources() -> Vec<BookmarkSourceDto> {
    crate::bookmarks::discover()
        .into_iter()
        .map(|s| {
            let count = crate::bookmarks::read_file(&s.path)
                .map(|b| b.len())
                .unwrap_or(0);
            BookmarkSourceDto {
                label: s.label,
                path: s.path.to_string_lossy().into_owned(),
                count,
            }
        })
        .collect()
}

/// Import bookmarks from one browser profile into the vault.
#[tauri::command]
pub fn import_bookmarks(state: St<'_>, path: String) -> Result<usize, CmdError> {
    do_import_bookmarks(state.inner(), std::path::Path::new(&path))
}

fn do_import_bookmarks(state: &Mutex<AppState>, path: &std::path::Path) -> Result<usize, CmdError> {
    let mut st = write_guard(state)?;
    let imported = crate::bookmarks::read_file(path)
        .map_err(|_| CmdError::new("read_failed", "Could not read that browser profile."))?;

    let added = {
        let vault = st.vault.as_mut().ok_or_else(CmdError::no_vault)?;
        if !vault.is_unlocked() {
            return Err(CmdError::new("locked", "Unlock Arca first."));
        }

        let mut seen: std::collections::HashSet<(String, String)> =
            std::collections::HashSet::new();
        if let Ok(summaries) = vault.list_items(false) {
            for s in summaries {
                let Ok(item) = vault.get_item(s.id) else {
                    continue;
                };
                if let vault_core::VaultItem::Bookmark { url, folder, .. } = &item.data {
                    seen.insert((url.clone(), folder.clone()));
                }
            }
        }

        let mut added = 0usize;
        for b in imported {
            if !seen.insert((b.url.clone(), b.folder.clone())) {
                continue;
            }
            let item = vault_core::Item::new(
                vault_core::VaultItem::Bookmark {
                    title: b.title,
                    url: b.url,
                    folder: b.folder,
                    notes: String::new(),
                },
                0,
            );
            if vault.upsert_item(item).is_ok() {
                added += 1;
            }
        }
        added
    };

    if added > 0 {
        st.store.snapshot_now();
        persist(&mut st)?;
    }
    st.touch();
    Ok(added)
}

#[tauri::command]
pub fn resolve_passkey_choice(app: tauri::AppHandle, id: String, item_id: Option<String>) {
    crate::bridge::resolve_passkey_choice(&app, &id, item_id);
}

// ---- tests (drive the do_* functions directly, no Tauri runtime) ----------

#[cfg(test)]
mod tests;
