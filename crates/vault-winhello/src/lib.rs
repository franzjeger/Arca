//! Windows Hello user-presence verification, parented to a real window.
//!
//! This replaces `robius-authentication` on Windows, whose implementation broke
//! Frank's keyboard: it parents the Hello prompt to `GetDesktopWindow()` — a
//! window that cannot legitimately receive focus for it — and then forces focus
//! with a synthesized Alt keypress (`keybd_event(VK_MENU, ...)`, borrowed from
//! Bitwarden). When anything interrupts between the synthetic Alt-down and
//! Alt-up, the key stays logically held: every subsequent keystroke becomes an
//! Alt-chord and the keyboard is unusable until something resets key state —
//! in practice, logging out.
//!
//! The OS way needs no tricks. `IUserConsentVerifierInterop::
//! RequestVerificationForWindowAsync` exists precisely so Win32 apps can parent
//! the prompt to THEIR window; a correctly-parented dialog takes focus by
//! itself. One rule remains ours to keep: never call this from a thread whose
//! message pump must keep running — the caller blocks on the operation, so it
//! must sit on a worker thread while the UI thread stays live.

#![cfg_attr(not(windows), allow(unused))]

/// Ask Windows Hello to verify the user, parented to `hwnd`.
///
/// `hwnd` is the raw window handle of a VISIBLE window the user is looking at
/// (Tauri's `window.hwnd()`). Blocks until the user answers; call it from a
/// worker thread, never the UI thread.
#[cfg(windows)]
pub fn verify(hwnd: isize, reason: &str) -> Result<(), String> {
    use windows::{
        core::{factory, HSTRING},
        Foundation::IAsyncOperation,
        Security::Credentials::UI::{
            UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability,
        },
        Win32::{Foundation::HWND, System::WinRT::IUserConsentVerifierInterop},
    };

    // Without this pre-check, RequestVerification hangs on machines where Hello
    // is not set up (documented behaviour, observed by everyone who skips it).
    let availability = UserConsentVerifier::CheckAvailabilityAsync()
        .and_then(|op| op.get())
        .map_err(|e| format!("Windows Hello availability check failed: {e}"))?;
    match availability {
        UserConsentVerifierAvailability::Available => {}
        UserConsentVerifierAvailability::DeviceNotPresent
        | UserConsentVerifierAvailability::NotConfiguredForUser => {
            return Err(
                "Windows Hello is not set up on this PC. Set it up in Settings ▸ Accounts ▸ \
                 Sign-in options, or unlock with your master password."
                    .to_string(),
            );
        }
        UserConsentVerifierAvailability::DisabledByPolicy => {
            return Err("Windows Hello is disabled by policy on this PC.".to_string());
        }
        _ => return Err("Windows Hello is unavailable right now.".to_string()),
    }

    let interop = factory::<UserConsentVerifier, IUserConsentVerifierInterop>()
        .map_err(|e| format!("Windows Hello interop factory failed: {e}"))?;

    // SAFETY: `hwnd` is a live top-level window handle supplied by Tauri for a
    // window we own; the interop method reads it and parents the system prompt
    // to it. The returned IAsyncOperation is a normal WinRT object with its own
    // lifetime management.
    let operation: IAsyncOperation<UserConsentVerificationResult> = unsafe {
        interop.RequestVerificationForWindowAsync(HWND(hwnd as *mut _), &HSTRING::from(reason))
    }
    .map_err(|e| format!("Windows Hello request failed: {e}"))?;

    // Blocks THIS thread until the user answers — which is the whole reason the
    // caller must not be the UI thread.
    let result = operation
        .get()
        .map_err(|e| format!("Windows Hello did not answer: {e}"))?;

    match result {
        UserConsentVerificationResult::Verified => Ok(()),
        UserConsentVerificationResult::Canceled => Err("Verification was cancelled.".to_string()),
        UserConsentVerificationResult::RetriesExhausted => {
            Err("Too many attempts. Try again in a moment.".to_string())
        }
        other => Err(format!("Verification was not confirmed ({other:?}).")),
    }
}
