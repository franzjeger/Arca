//! Biometric (Touch ID on macOS, Windows Hello on Windows) gate for quick unlock.
//!
//! This is a *presence* gate placed in front of the keychain-backed quick
//! unlock: before the app uses the stored device key to unlock the vault, the
//! device owner must authenticate with Touch ID (falling back to the login
//! password). It does **not** change how the device key is stored.
//!
//! Security note: the device key itself stays protected by the OS keychain
//! (see `vault-store`), not by this prompt. A process running as the same user
//! (threat T9 in `THREAT_MODEL.md`, explicitly out of scope) could still read
//! the keychain entry directly without passing this prompt. OS-enforced
//! biometric gating of the key itself (a `SecAccessControl`-protected keychain
//! item that the OS will not release without Touch ID) is the stronger,
//! Apple-equivalent design and is tracked as a hardening follow-up.
//!
//! The unsafe interop lives in `robius-authentication` (macOS) and the
//! `vault-winhello` crate (Windows); this module uses only their safe APIs,
//! so the crate-wide `#![forbid(unsafe_code)]` still holds.

/// Whether biometric authentication is wired on this platform.
#[cfg(any(target_os = "macos", target_os = "windows"))]
pub fn available() -> bool {
    true
}

/// Windows: Hello, parented to the app's main window.
///
/// The parenting is the fix. The previous implementation (robius) parented the
/// prompt to the DESKTOP window — which cannot legitimately take focus for it —
/// and then forced focus with a synthesized Alt keypress; interrupted half-way,
/// that left Alt logically held and the keyboard unusable until logout.
/// A prompt parented to a real visible window takes focus by itself.
///
/// Still blocking, so the same rule as ever applies — and applies HARDER here:
/// the caller must not be the main thread, because the dialog needs our message
/// pump alive to paint and to hand focus back afterwards.
#[cfg(target_os = "windows")]
pub fn authenticate(app: Option<&tauri::AppHandle>, reason: &str) -> Result<(), String> {
    use tauri::Manager;
    let hwnd = app
        .and_then(|a| a.get_webview_window("main"))
        .and_then(|w| w.hwnd().ok())
        .ok_or_else(|| "No window to attach the Windows Hello prompt to.".to_string())?;
    vault_winhello::verify(hwnd.0 as isize, &format!("Arca is trying to {reason}."))
}

/// Whether biometric authentication is wired on this platform.
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub fn available() -> bool {
    false
}

/// Prompt the device owner to authenticate. `Ok(())` means they succeeded;
/// `Err(message)` means they cancelled, failed, or biometrics are unavailable.
///
/// `reason` is shown to the user as "Arca is trying to <reason>".
/// This call **blocks** until the user responds, so callers must not hold the
/// app-state lock while invoking it.
#[cfg(target_os = "macos")]
pub fn authenticate(_app: Option<&tauri::AppHandle>, reason: &str) -> Result<(), String> {
    use robius_authentication::{
        AndroidText, BiometricStrength, Context, PolicyBuilder, Text, WindowsText,
    };

    let policy = PolicyBuilder::new()
        .biometrics(Some(BiometricStrength::Strong))
        // Allow the login password / Apple Watch as a fallback when a finger
        // isn't recognised, so the user is never locked out of quick unlock.
        .password(true)
        .watch(true)
        .build()
        .ok_or_else(|| "Biometric authentication is not available on this device.".to_string())?;

    let text = Text {
        // `apple` is shown on macOS, `windows` on Windows (Windows Hello); the
        // remaining field is required by the struct but unused on both.
        android: AndroidText {
            title: reason,
            subtitle: None,
            description: None,
        },
        apple: reason,
        windows: WindowsText::new("Arca", reason)
            .unwrap_or_else(|| WindowsText::new_truncated("Arca", reason)),
    };

    Context::new(())
        .blocking_authenticate(text, &policy)
        .map_err(|e| format!("Verification was not confirmed ({e:?})."))
}

/// On platforms without a biometric provider wired up yet, this is a no-op so
/// the existing (non-biometric) quick unlock keeps working unchanged.
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub fn authenticate(_app: Option<&tauri::AppHandle>, _reason: &str) -> Result<(), String> {
    Ok(())
}
